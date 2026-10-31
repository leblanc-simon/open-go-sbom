package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
)

// DefaultChunkSize est la taille des blocs d'une archive en base.
const DefaultChunkSize = 8 << 20

// RescanAllKind est le job mis en file à chaque changement de cible : il réanalyse toutes
// les références actives (handler dans internal/finding).
const RescanAllKind = "analysis.rescan_all"

// RescanAllPayload est la charge d'un job analysis.rescan_all : l'archive devenue cible
// (information ; le handler relit la cible).
type RescanAllPayload struct {
	ArchiveID uuid.UUID `json:"archive_id"`
}

// ErrArchiveNotFound : archive inconnue.
var ErrArchiveNotFound = errors.New("vuln: archive introuvable")

// Origin dit d'où vient une archive.
type Origin string

// Origines d'une archive.
const (
	OriginDownload Origin = "download"
	OriginImport   Origin = "import"
)

// Archive est une archive vérifiée de la base, stockée en base de données.
type Archive struct {
	ID         uuid.UUID
	SHA256     string // hexadécimal
	Size       int64
	Chunks     int
	Schema     string
	Built      time.Time
	Origin     Origin
	SourceURL  string
	CreatedAt  time.Time
	IsTarget   bool
	TargetedAt *time.Time
}

// Version renvoie la version de base que porte l'archive.
func (a Archive) Version() Version {
	return Version{ArchiveID: a.ID, Built: a.Built, Schema: a.Schema}
}

// State est l'état de la base commune.
type State struct {
	// Target est l'archive cible ; nil tant qu'aucune base n'a été obtenue.
	Target         *Archive
	LastCheckAt    *time.Time
	LastCheckError string
}

// Stale indique une base cible plus vieille que maxAge (ou absente).
func (s State) Stale(now time.Time, maxAge time.Duration) bool {
	return s.Target == nil || now.Sub(s.Target.Built) > maxAge
}

const archiveColumns = `a.id, a.sha256, a.size, a.chunk_count, a.schema, a.built_at, a.origin, a.source_url, a.created_at,
	s.target_archive_id IS NOT DISTINCT FROM a.id, CASE WHEN s.target_archive_id = a.id THEN s.target_set_at END`

type scanner interface{ Scan(dest ...any) error }

func scanArchive(row scanner) (Archive, error) {
	var a Archive
	var sum []byte
	var origin string
	var targeted sql.NullTime
	if err := row.Scan(&a.ID, &sum, &a.Size, &a.Chunks, &a.Schema, &a.Built, &origin, &a.SourceURL, &a.CreatedAt,
		&a.IsTarget, &targeted); err != nil {
		return Archive{}, err
	}
	a.SHA256, a.Origin, a.Built, a.CreatedAt = hex.EncodeToString(sum), Origin(origin), a.Built.UTC(), a.CreatedAt.UTC()
	if targeted.Valid {
		t := targeted.Time.UTC()
		a.TargetedAt = &t
	}
	return a, nil
}

// ReadState lit l'état de la base commune.
func ReadState(ctx context.Context, q db.Querier) (State, error) {
	var s State
	var target uuid.NullUUID
	var checked sql.NullTime
	err := q.QueryRowContext(ctx, `SELECT target_archive_id, last_check_at, last_check_error FROM vulndb_state`).
		Scan(&target, &checked, &s.LastCheckError)
	if err != nil {
		return State{}, fmt.Errorf("vuln: état de la base : %w", err)
	}
	if checked.Valid {
		t := checked.Time.UTC()
		s.LastCheckAt = &t
	}
	if target.Valid {
		a, err := GetArchive(ctx, q, target.UUID)
		if err != nil {
			return State{}, err
		}
		s.Target = &a
	}
	return s, nil
}

// TargetVersion lit la version cible ; zéro sans base.
func TargetVersion(ctx context.Context, q db.Querier) (Version, error) {
	var v Version
	var id uuid.NullUUID
	var built sql.NullTime
	var schema sql.NullString
	err := q.QueryRowContext(ctx, `SELECT s.target_archive_id, a.built_at, a.schema FROM vulndb_state s
		LEFT JOIN vulndb_archives a ON a.id = s.target_archive_id`).Scan(&id, &built, &schema)
	if err != nil {
		return Version{}, fmt.Errorf("vuln: version cible : %w", err)
	}
	if id.Valid {
		v = Version{ArchiveID: id.UUID, Built: built.Time.UTC(), Schema: schema.String}
	}
	return v, nil
}

// GetArchive lit une archive.
func GetArchive(ctx context.Context, q db.Querier, id uuid.UUID) (Archive, error) {
	a, err := scanArchive(q.QueryRowContext(ctx, `SELECT `+archiveColumns+` FROM vulndb_archives a CROSS JOIN vulndb_state s
		WHERE a.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Archive{}, ErrArchiveNotFound
	}
	if err != nil {
		return Archive{}, fmt.Errorf("vuln: archive %s : %w", id, err)
	}
	return a, nil
}

// ListArchives renvoie les limit archives les plus récentes (par date de construction).
func ListArchives(ctx context.Context, q db.Querier, limit int) ([]Archive, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+archiveColumns+` FROM vulndb_archives a CROSS JOIN vulndb_state s
		ORDER BY a.built_at DESC, a.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("vuln: archives : %w", err)
	}
	defer rows.Close()
	var out []Archive
	for rows.Next() {
		a, err := scanArchive(rows)
		if err != nil {
			return nil, fmt.Errorf("vuln: archives : %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func archiveBySHA(ctx context.Context, q db.Querier, sum []byte) (Archive, error) {
	a, err := scanArchive(q.QueryRowContext(ctx, `SELECT `+archiveColumns+` FROM vulndb_archives a CROSS JOIN vulndb_state s
		WHERE a.sha256 = $1`, sum))
	if errors.Is(err, sql.ErrNoRows) {
		return Archive{}, ErrArchiveNotFound
	}
	return a, err
}

// NewArchive décrit une archive à stocker.
type NewArchive struct {
	SHA256    []byte
	Size      int64
	Desc      Description
	Origin    Origin
	SourceURL string
}

// putArchive écrit l'archive lue dans r (déjà vérifiée) bloc par bloc dans la transaction
// de l'appelant, puis relit sa somme : un fichier modifié entre la vérification et
// l'écriture est refusé.
func putArchive(ctx context.Context, tx *db.Tx, r io.Reader, n NewArchive, chunkSize int, now time.Time) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	chunks := int((n.Size + int64(chunkSize) - 1) / int64(chunkSize))
	if _, err := tx.ExecContext(ctx, `INSERT INTO vulndb_archives (id, sha256, size, chunk_count, schema, built_at, origin, source_url, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, n.SHA256, n.Size, chunks, n.Desc.Schema, n.Desc.Built.Round(time.Microsecond), string(n.Origin), n.SourceURL, now); err != nil {
		return uuid.Nil, fmt.Errorf("vuln: archive : %w", err)
	}
	h := sha256.New()
	buf := make([]byte, chunkSize)
	var total int64
	for seq := 0; ; seq++ {
		k, err := io.ReadFull(r, buf)
		if k > 0 {
			h.Write(buf[:k])
			total += int64(k)
			if _, err := tx.ExecContext(ctx, `INSERT INTO vulndb_archive_chunks (archive_id, seq, data) VALUES ($1, $2, $3)`,
				id, seq, buf[:k]); err != nil {
				return uuid.Nil, fmt.Errorf("vuln: bloc %d de l'archive : %w", seq, err)
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return uuid.Nil, fmt.Errorf("vuln: lecture de l'archive : %w", err)
		}
	}
	if total != n.Size || !bytes.Equal(h.Sum(nil), n.SHA256) {
		return uuid.Nil, ErrChecksum
	}
	return id, nil
}

// setTarget fait de l'archive id la cible commune et met en file la réanalyse de tout le
// parc, dans la transaction de l'appelant. Sans effet si elle l'est déjà.
func setTarget(ctx context.Context, tx *db.Tx, id uuid.UUID, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx, `UPDATE vulndb_state SET target_archive_id = $1, target_set_at = $2
		WHERE target_archive_id IS DISTINCT FROM $1`, id, now)
	if err != nil {
		return false, fmt.Errorf("vuln: cible : %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: RescanAllKind, Payload: RescanAllPayload{ArchiveID: id},
		Priority: jobs.PriorityLow, UniqueKey: RescanAllKind}); err != nil {
		return false, fmt.Errorf("vuln: mise en file de la réanalyse : %w", err)
	}
	return true, nil
}

// recordCheck note le résultat d'une vérification de la liste de distribution.
func recordCheck(ctx context.Context, q db.Querier, now time.Time, checkErr error) error {
	msg := ""
	if checkErr != nil {
		msg = clipText(checkErr.Error(), 500)
	}
	_, err := q.ExecContext(ctx, `UPDATE vulndb_state SET last_check_at = $1, last_check_error = $2`, now, msg)
	return err
}

// copyArchive écrit l'archive a dans w et vérifie sa taille et sa somme.
func copyArchive(ctx context.Context, pool *db.Pool, a Archive, w io.Writer) error {
	return copyChunks(ctx, pool, `SELECT data FROM vulndb_archive_chunks WHERE archive_id = $1 AND seq = $2`,
		chunkSet{id: a.ID, count: a.Chunks, size: a.Size, sha256: a.SHA256}, w)
}

// chunkSet décrit un fichier rangé par blocs (archive ou import).
type chunkSet struct {
	id     uuid.UUID
	count  int
	size   int64
	sha256 string // hexadécimal
}

// copyChunks écrit les blocs de c dans w, lus par query ($1 : identifiant, $2 : rang),
// une requête par bloc (la mémoire reste bornée à un bloc), et vérifie taille et somme.
func copyChunks(ctx context.Context, pool *db.Pool, query string, c chunkSet, w io.Writer) error {
	h := sha256.New()
	out := io.MultiWriter(w, h)
	var total int64
	for seq := 0; seq < c.count; seq++ {
		var data []byte
		err := pool.InTx(ctx, func(tx *db.Tx) error {
			return tx.QueryRowContext(ctx, query, c.id, seq).Scan(&data)
		}, db.ReadOnly())
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w : bloc %d manquant", ErrChecksum, seq)
		}
		if err != nil {
			return fmt.Errorf("vuln: bloc %d de %s : %w", seq, c.id, err)
		}
		if _, err := out.Write(data); err != nil {
			return err
		}
		total += int64(len(data))
	}
	if total != c.size || hex.EncodeToString(h.Sum(nil)) != c.sha256 {
		return ErrChecksum
	}
	return nil
}

// Purged résume une purge des archives.
type Purged struct {
	Archives int
	Bytes    int64
}

// PurgeArchives supprime toutes les archives qui ne sont pas la cible et journalise la
// purge, dans une transaction. La ligne d'état est verrouillée d'abord : une nouvelle
// cible fixée en même temps (vérification, import) attend la fin de la purge, et
// l'archive cible n'est jamais supprimée. Les constats gardent l'identifiant de l'archive
// qui les a produits, sans clé étrangère ; une instance encore sur une ancienne base se
// synchronise sur la cible.
func PurgeArchives(ctx context.Context, pool *db.Pool, actor audit.Actor) (Purged, error) {
	var p Purged
	err := pool.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM vulndb_state FOR UPDATE`); err != nil {
			return fmt.Errorf("vuln: verrou de l'état : %w", err)
		}
		err := tx.QueryRowContext(ctx, `
			WITH gone AS (
				DELETE FROM vulndb_archives a USING vulndb_state s
				WHERE a.id IS DISTINCT FROM s.target_archive_id
				RETURNING a.size
			)
			SELECT count(*), COALESCE(sum(size), 0) FROM gone`).Scan(&p.Archives, &p.Bytes)
		if err != nil {
			return fmt.Errorf("vuln: purge des archives : %w", err)
		}
		return audit.RecordInstance(ctx, tx, actor, audit.Event{Action: audit.VulnDBArchivesPurged, TargetType: "vulndb",
			Details: map[string]string{"archives": strconv.Itoa(p.Archives), "bytes": strconv.FormatInt(p.Bytes, 10)}})
	})
	if err != nil {
		return Purged{}, err
	}
	return p, nil
}
