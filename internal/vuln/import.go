package vuln

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/jobs"
)

// ImportKind est le job qui installe une archive téléversée par l'exploitant (Import).
// Il s'exécute sur une instance worker, qui n'est pas forcément celle qui a reçu le
// fichier : l'archive passe par PostgreSQL (vulndb_import_chunks).
const ImportKind = "vulndb.import"

// importAttempts borne les tentatives d'un import : une installation dure plusieurs
// minutes, et une archive invalide est refusée dès la première.
const importAttempts = 3

// finishTimeout borne l'enregistrement de la fin d'un import, qui se fait même quand le
// délai du job a expiré.
const finishTimeout = 10 * time.Second

// ImportStatus est l'état d'un import manuel.
type ImportStatus string

// États d'un import (migration 014).
const (
	ImportUploading ImportStatus = "uploading"
	ImportQueued    ImportStatus = "queued"
	ImportDone      ImportStatus = "done"
	ImportFailed    ImportStatus = "failed"
)

var (
	// ErrImportInProgress : un autre import est en cours de téléversement ou d'installation.
	ErrImportInProgress = errors.New("vuln: un import est déjà en cours")
	// ErrImportNotFound : import inconnu.
	ErrImportNotFound = errors.New("vuln: import introuvable")
	// errImportAbandoned : le téléversement a été déclaré abandonné pendant qu'il se
	// poursuivait (trop lent).
	errImportAbandoned = errors.New("vuln: téléversement abandonné")
)

// Import est un import manuel d'archive.
type Import struct {
	ID          uuid.UUID
	Status      ImportStatus
	Size        int64
	Chunks      int
	SHA256      string // hexadécimal, vide pendant le téléversement
	FileName    string
	RequestedBy string // adresse du compte qui a téléversé
	ArchiveID   *uuid.UUID
	Error       string
	CreatedAt   time.Time
	FinishedAt  *time.Time
}

// ImportPayload est la charge d'un job vulndb.import.
type ImportPayload struct {
	ImportID uuid.UUID `json:"import_id"`
}

// UploadOptions règle un téléversement (Upload).
type UploadOptions struct {
	// MaxSize borne l'archive (vulndb.max_archive_mib).
	MaxSize int64
	// ChunkSize est la taille des blocs (0 : DefaultChunkSize).
	ChunkSize int
	// StaleAfter : un téléversement qui n'a rien écrit depuis StaleAfter est abandonné à
	// la tentative suivante (processus tué en cours de route).
	StaleAfter time.Duration
	FileName   string
	Actor      audit.Actor
	Now        func() time.Time
}

// Upload range l'archive lue dans r par blocs (un bloc par transaction : aucune
// transaction ne dure le temps du téléversement), puis, dans une dernière transaction,
// la déclare complète, met en file le job vulndb.import et journalise la demande.
// ErrImportInProgress si un autre import n'est pas terminé, ErrTooLarge au-delà de
// MaxSize, ErrInvalidArchive pour un fichier vide. En cas d'échec, rien ne reste en base.
func Upload(ctx context.Context, pool *db.Pool, r io.Reader, o UploadOptions) (Import, error) {
	if o.ChunkSize <= 0 {
		o.ChunkSize = DefaultChunkSize
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Import{}, err
	}
	if err := beginUpload(ctx, pool, id, o); err != nil {
		return Import{}, err
	}
	imp, err := writeUpload(ctx, pool, id, r, o)
	if err != nil {
		// Le contexte de la requête peut être annulé (client parti) : le nettoyage passe quand
		// même.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
		defer cancel()
		if _, derr := pool.DB().ExecContext(cleanup, `DELETE FROM vulndb_imports WHERE id = $1 AND status = 'uploading'`, id); derr != nil {
			err = errors.Join(err, fmt.Errorf("vuln: nettoyage du téléversement : %w", derr))
		}
		return Import{}, err
	}
	return imp, nil
}

// beginUpload abandonne les imports bloqués (téléversement interrompu, job disparu),
// puis crée celui-ci, s'il est seul en cours.
func beginUpload(ctx context.Context, pool *db.Pool, id uuid.UUID, o UploadOptions) error {
	return pool.InTx(ctx, func(tx *db.Tx) error {
		now := o.Now()
		// L'index unique vulndb_imports_active garantit au plus une ligne en cours.
		var cur uuid.UUID
		var status ImportStatus
		var stale bool
		err := tx.QueryRowContext(ctx, `SELECT id, status, updated_at < $1 FROM vulndb_imports
			WHERE status IN ('uploading', 'queued') FOR UPDATE`, now.Add(-o.StaleAfter)).Scan(&cur, &status, &stale)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("vuln: import en cours : %w", err)
		}
		var stuck []uuid.UUID
		switch {
		case err != nil:
		case status == ImportUploading && stale:
			stuck = append(stuck, cur)
		case status == ImportQueued:
			active, err := jobs.Active(ctx, tx, ImportKind, importKey(cur))
			if err != nil {
				return err
			}
			if !active {
				stuck = append(stuck, cur)
			}
		}
		for _, s := range stuck {
			if err := endImport(ctx, tx, s, nil, errImportAbandoned, now); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO vulndb_imports (id, status, file_name, requested_by, created_at, updated_at)
			VALUES ($1, 'uploading', $2, $3, $4, $4) ON CONFLICT DO NOTHING`,
			id, clipText(o.FileName, 255), clipText(o.Actor.Email, 320), now)
		if err != nil {
			return fmt.Errorf("vuln: création de l'import : %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrImportInProgress
		}
		return nil
	})
}

func importKey(id uuid.UUID) string { return "vulndb_import:" + id.String() }

// writeUpload écrit les blocs, puis met l'import en file.
func writeUpload(ctx context.Context, pool *db.Pool, id uuid.UUID, r io.Reader, o UploadOptions) (Import, error) {
	h := sha256.New()
	buf := make([]byte, o.ChunkSize)
	var size int64
	seq := 0
	for {
		k, rerr := io.ReadFull(r, buf)
		if k > 0 {
			size += int64(k)
			if size > o.MaxSize {
				return Import{}, ErrTooLarge
			}
			h.Write(buf[:k])
			if err := pool.InTx(ctx, func(tx *db.Tx) error {
				res, err := tx.ExecContext(ctx, `UPDATE vulndb_imports SET updated_at = $2 WHERE id = $1 AND status = 'uploading'`,
					id, o.Now())
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n == 0 {
					return errImportAbandoned
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO vulndb_import_chunks (import_id, seq, data) VALUES ($1, $2, $3)`,
					id, seq, buf[:k])
				return err
			}); err != nil {
				return Import{}, fmt.Errorf("vuln: bloc %d du téléversement : %w", seq, err)
			}
			seq++
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return Import{}, fmt.Errorf("vuln: lecture du téléversement : %w", rerr)
		}
	}
	if size == 0 {
		return Import{}, fmt.Errorf("%w : archive vide", ErrInvalidArchive)
	}
	sum := h.Sum(nil)
	var imp Import
	err := pool.InTx(ctx, func(tx *db.Tx) error {
		now := o.Now()
		res, err := tx.ExecContext(ctx, `UPDATE vulndb_imports SET status = 'queued', size = $2, chunk_count = $3, sha256 = $4, updated_at = $5
			WHERE id = $1 AND status = 'uploading'`, id, size, seq, sum, now)
		if err != nil {
			return fmt.Errorf("vuln: fin du téléversement : %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errImportAbandoned
		}
		if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: ImportKind, Payload: ImportPayload{ImportID: id},
			Priority: jobs.PriorityHigh, UniqueKey: importKey(id), MaxAttempts: importAttempts}); err != nil {
			return fmt.Errorf("vuln: mise en file de l'import : %w", err)
		}
		if err := audit.RecordInstance(ctx, tx, o.Actor, audit.Event{Action: audit.VulnDBImportRequested,
			TargetType: "vulndb_import", TargetID: id.String(), TargetLabel: o.FileName,
			Details: map[string]string{"sha256": hex.EncodeToString(sum), "size": strconv.FormatInt(size, 10)}}); err != nil {
			return err
		}
		imp, err = GetImport(ctx, tx, id)
		return err
	})
	return imp, err
}

const importColumns = `id, status, size, chunk_count, sha256, file_name, requested_by, archive_id, error, created_at, finished_at`

func scanImport(row scanner) (Import, error) {
	var imp Import
	var status string
	var sum []byte
	var archive uuid.NullUUID
	var finished sql.NullTime
	if err := row.Scan(&imp.ID, &status, &imp.Size, &imp.Chunks, &sum, &imp.FileName, &imp.RequestedBy, &archive, &imp.Error,
		&imp.CreatedAt, &finished); err != nil {
		return Import{}, err
	}
	imp.Status, imp.SHA256, imp.CreatedAt = ImportStatus(status), hex.EncodeToString(sum), imp.CreatedAt.UTC()
	if archive.Valid {
		imp.ArchiveID = &archive.UUID
	}
	if finished.Valid {
		t := finished.Time.UTC()
		imp.FinishedAt = &t
	}
	return imp, nil
}

// GetImport lit un import.
func GetImport(ctx context.Context, q db.Querier, id uuid.UUID) (Import, error) {
	imp, err := scanImport(q.QueryRowContext(ctx, `SELECT `+importColumns+` FROM vulndb_imports WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Import{}, ErrImportNotFound
	}
	if err != nil {
		return Import{}, fmt.Errorf("vuln: import %s : %w", id, err)
	}
	return imp, nil
}

// ListImports renvoie les limit imports les plus récents.
func ListImports(ctx context.Context, q db.Querier, limit int) ([]Import, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+importColumns+` FROM vulndb_imports ORDER BY created_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("vuln: imports : %w", err)
	}
	defer rows.Close()
	var out []Import
	for rows.Next() {
		imp, err := scanImport(rows)
		if err != nil {
			return nil, fmt.Errorf("vuln: imports : %w", err)
		}
		out = append(out, imp)
	}
	return out, rows.Err()
}

// endImport termine un import en cours (archive non nil : réussi ; sinon échoué avec
// cause), supprime ses blocs et journalise la fin, dans la transaction de l'appelant.
func endImport(ctx context.Context, tx *db.Tx, id uuid.UUID, a *Archive, cause error, now time.Time) error {
	status, action, msg := ImportDone, audit.VulnDBImported, ""
	var archive uuid.NullUUID
	details := map[string]string{}
	if a != nil {
		archive = uuid.NullUUID{UUID: a.ID, Valid: true}
		details["archive"], details["built"] = a.ID.String(), a.Built.Format(time.RFC3339)
	} else {
		status, action, msg = ImportFailed, audit.VulnDBImportFailed, clipText(cause.Error(), 500)
		details["error"] = msg
	}
	var name string
	err := tx.QueryRowContext(ctx, `UPDATE vulndb_imports SET status = $2, archive_id = $3, error = $4, finished_at = $5, updated_at = $5
		WHERE id = $1 AND status IN ('uploading', 'queued') RETURNING file_name`, id, string(status), archive, msg, now).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // déjà terminé
	}
	if err != nil {
		return fmt.Errorf("vuln: fin de l'import %s : %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulndb_import_chunks WHERE import_id = $1`, id); err != nil {
		return fmt.Errorf("vuln: blocs de l'import %s : %w", id, err)
	}
	return audit.RecordInstance(ctx, tx, audit.System, audit.Event{Action: action, TargetType: "vulndb_import",
		TargetID: id.String(), TargetLabel: name, Details: details})
}

// ImportHandler est le handler du job vulndb.import : il recopie l'archive téléversée
// dans le répertoire local, la vérifie et l'installe comme Import, puis termine l'import
// et en supprime les blocs. Une archive invalide est refusée sans nouvel essai ; une
// autre erreur est réessayée, et la dernière tentative termine l'import en échec.
// Idempotent : un import déjà terminé est ignoré, une archive déjà stockée redevient la
// cible.
func (c *Checker) ImportHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p ImportPayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		imp, err := GetImport(ctx, c.o.Pool.DB(), p.ImportID)
		if errors.Is(err, ErrImportNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if imp.Status != ImportQueued {
			return nil
		}
		a, err := c.installImport(ctx, imp)
		if err != nil && !errors.Is(err, ErrInvalidArchive) && !errors.Is(err, ErrChecksum) && !errors.Is(err, ErrTooLarge) &&
			e.Attempt < e.MaxAttempts {
			return err
		}
		if err != nil {
			c.o.Logger.Warn("import de la base de vulnérabilités refusé", "import", imp.ID, "err", err)
		} else {
			c.o.Logger.Info("base de vulnérabilités importée", "import", imp.ID, "archive", a.ID, "built", a.Built)
		}
		done, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
		defer cancel()
		return c.o.Pool.InTx(done, func(tx *db.Tx) error {
			var ap *Archive
			if err == nil {
				ap = &a
			}
			return endImport(done, tx, imp.ID, ap, err, c.o.Now())
		})
	})
}

// installImport recopie l'import dans un fichier temporaire de Dir et l'importe.
func (c *Checker) installImport(ctx context.Context, imp Import) (Archive, error) {
	if err := os.MkdirAll(c.o.Dir, 0o700); err != nil {
		return Archive{}, fmt.Errorf("vuln: répertoire local : %w", err)
	}
	f, err := os.CreateTemp(c.o.Dir, ".import-*.archive")
	if err != nil {
		return Archive{}, fmt.Errorf("vuln: fichier d'import : %w", err)
	}
	defer os.Remove(f.Name())
	err = copyChunks(ctx, c.o.Pool, `SELECT data FROM vulndb_import_chunks WHERE import_id = $1 AND seq = $2`,
		chunkSet{id: imp.ID, count: imp.Chunks, size: imp.Size, sha256: imp.SHA256}, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Archive{}, err
	}
	return c.Import(ctx, f.Name())
}
