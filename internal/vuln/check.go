package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/jobs"
)

// CheckKind est le job qui interroge la liste de distribution et obtient la nouvelle base.
const CheckKind = "vulndb.check"

// CheckSchedule passe toutes les every : une seule instance l'exécute (§ 16).
func CheckSchedule(every time.Duration) jobs.Schedule {
	return jobs.Schedule{Name: CheckKind, Every: every, Job: jobs.Job{Kind: CheckKind, Priority: jobs.PriorityNormal}}
}

// installDir est le répertoire local de l'archive id sous root.
func installDir(root string, a Archive) string { return filepath.Join(root, a.ID.String()) }

// CheckerOptions règle un Checker.
type CheckerOptions struct {
	Pool   *db.Pool
	Source Source
	Engine Engine
	// Dir est le répertoire local des bases (vulndb.dir), partagé avec le Manager de
	// l'instance : la base validée par une vérification y reste installée.
	Dir string
	// MaxArchive borne la taille d'une archive téléchargée ou importée.
	MaxArchive int64
	// ChunkSize est la taille des blocs en base (0 : DefaultChunkSize).
	ChunkSize int
	Logger    *slog.Logger
	Now        func() time.Time
}

// Checker obtient les nouvelles bases : téléchargement (vulndb.check) ou import. Une
// archive n'est stockée et ne devient la cible qu'après vérification de sa somme et une
// installation complète qui ouvre la base.
type Checker struct {
	o CheckerOptions
}

// NewChecker renvoie un Checker.
func NewChecker(o CheckerOptions) *Checker {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = DefaultChunkSize
	}
	return &Checker{o: o}
}

// Handler est le handler du job CheckKind.
func (c *Checker) Handler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		_, err := c.Check(ctx)
		return err
	})
}

// Check interroge la liste de distribution et, si elle annonce une base plus récente que
// la cible, la télécharge, la vérifie, la stocke et en fait la cible. Il renvoie l'archive
// cible après coup (nil sans base). Idempotent : une archive déjà stockée n'est pas
// retéléchargée.
func (c *Checker) Check(ctx context.Context) (*Archive, error) {
	pool := c.o.Pool
	st, err := ReadState(ctx, pool.DB())
	if err != nil {
		return nil, err
	}
	l, err := c.o.Source.Latest(ctx)
	if err != nil {
		return st.Target, c.fail(ctx, err)
	}
	if st.Target != nil && (st.Target.SHA256 == l.SHA256 || !l.Built.After(st.Target.Built)) {
		return st.Target, recordCheck(ctx, pool.DB(), c.o.Now(), nil)
	}
	sum, err := hex.DecodeString(l.SHA256)
	if err != nil || len(sum) != sha256.Size {
		return st.Target, c.fail(ctx, fmt.Errorf("vuln: somme annoncée %q illisible", l.SHA256))
	}
	if a, err := archiveBySHA(ctx, pool.DB(), sum); err == nil {
		err = pool.InTx(ctx, func(tx *db.Tx) error {
			if _, err := setTarget(ctx, tx, a.ID, c.o.Now()); err != nil {
				return err
			}
			return recordCheck(ctx, tx, c.o.Now(), nil)
		})
		return &a, err
	} else if !errors.Is(err, ErrArchiveNotFound) {
		return st.Target, err
	}
	path, got, size, err := c.download(ctx, l)
	if path != "" {
		defer os.Remove(path)
	}
	if err != nil {
		return st.Target, c.fail(ctx, err)
	}
	if got != l.SHA256 {
		return st.Target, c.fail(ctx, fmt.Errorf("%w : %s au lieu de %s", ErrChecksum, got, l.SHA256))
	}
	a, err := c.store(ctx, path, sum, size, OriginDownload, l.URL)
	if err != nil {
		return st.Target, c.fail(ctx, err)
	}
	c.o.Logger.Info("nouvelle base de vulnérabilités", "archive", a.ID, "built", a.Built, "schema", a.Schema, "size", a.Size)
	return &a, nil
}

// fail note l'échec d'une vérification et le renvoie (le job sera réessayé).
func (c *Checker) fail(ctx context.Context, err error) error {
	if rerr := recordCheck(ctx, c.o.Pool.DB(), c.o.Now(), err); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

func (c *Checker) download(ctx context.Context, l Listing) (string, string, int64, error) {
	if err := os.MkdirAll(c.o.Dir, 0o700); err != nil {
		return "", "", 0, fmt.Errorf("vuln: répertoire local : %w", err)
	}
	f, err := os.CreateTemp(c.o.Dir, ".download-*.tar.zst")
	if err != nil {
		return "", "", 0, fmt.Errorf("vuln: fichier de téléchargement : %w", err)
	}
	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, h)}
	err = c.o.Source.Download(ctx, l, cw, c.o.MaxArchive)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), cw.n, err
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Import stocke une archive fournie par l'exploitant (site isolé) et en fait la cible,
// après les mêmes vérifications qu'un téléchargement, la somme en moins (aucune liste ne
// l'annonce). Une archive déjà stockée devient simplement la cible.
func (c *Checker) Import(ctx context.Context, path string) (Archive, error) {
	f, err := os.Open(path)
	if err != nil {
		return Archive{}, fmt.Errorf("vuln: import : %w", err)
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(f, c.o.MaxArchive+1))
	_ = f.Close()
	if err != nil {
		return Archive{}, fmt.Errorf("vuln: import : %w", err)
	}
	if size > c.o.MaxArchive {
		return Archive{}, ErrTooLarge
	}
	if size == 0 {
		return Archive{}, fmt.Errorf("vuln: import : archive vide")
	}
	sum := h.Sum(nil)
	if a, err := archiveBySHA(ctx, c.o.Pool.DB(), sum); err == nil {
		err = c.o.Pool.InTx(ctx, func(tx *db.Tx) error {
			_, err := setTarget(ctx, tx, a.ID, c.o.Now())
			return err
		})
		return a, err
	} else if !errors.Is(err, ErrArchiveNotFound) {
		return Archive{}, err
	}
	return c.store(ctx, path, sum, size, OriginImport, "")
}

// store valide l'archive par une installation complète, puis la stocke et en fait la
// cible dans une seule transaction. L'installation validée reste dans Dir, là où le
// Manager de l'instance la cherche.
func (c *Checker) store(ctx context.Context, path string, sum []byte, size int64, origin Origin, url string) (Archive, error) {
	staging, err := os.MkdirTemp(c.o.Dir, ".validate-")
	if err != nil {
		return Archive{}, fmt.Errorf("vuln: répertoire de validation : %w", err)
	}
	defer os.RemoveAll(staging)
	dbDir := filepath.Join(staging, "db")
	desc, err := c.o.Engine.Install(ctx, path, dbDir)
	if err != nil {
		return Archive{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Archive{}, err
	}
	defer f.Close()
	var a Archive
	err = c.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		now := c.o.Now()
		id, err := putArchive(ctx, tx, f, NewArchive{SHA256: sum, Size: size, Desc: desc, Origin: origin, SourceURL: url}, c.o.ChunkSize, now)
		if err != nil {
			return err
		}
		if _, err := setTarget(ctx, tx, id, now); err != nil {
			return err
		}
		if origin == OriginDownload {
			if err := recordCheck(ctx, tx, now, nil); err != nil {
				return err
			}
		}
		a, err = GetArchive(ctx, tx, id)
		return err
	})
	if err != nil {
		return Archive{}, err
	}
	if err := os.Rename(dbDir, installDir(c.o.Dir, a)); err == nil {
		c.o.Logger.Debug("base validée gardée pour l'instance", "archive", a.ID)
	}
	return a, nil
}
