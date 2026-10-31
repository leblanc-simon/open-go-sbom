package inventory

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/sbom"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// UsageMax borne la liste des usages d'un composant.
const UsageMax = 500

// Component est un composant de l'organisation.
type Component struct {
	ID       uuid.UUID
	PURL     string
	PURLBase string
	Type     string
	Name     string
	Version  string
	CPEs     []string
	Hashes   []string
}

// GetComponent lit le composant id.
func GetComponent(ctx context.Context, tx *db.OrgTx, id uuid.UUID) (Component, error) {
	var c Component
	err := tx.QueryRowContext(ctx, `SELECT id, purl, purl_base, type, name, version, cpes, hashes FROM components WHERE id = $1`, id).
		Scan(&c.ID, &c.PURL, &c.PURLBase, &c.Type, &c.Name, &c.Version, db.Array(&c.CPEs), db.Array(&c.Hashes))
	if errors.Is(err, sql.ErrNoRows) {
		return Component{}, ErrNotFound
	}
	return c, wrap("composant", err)
}

// Usage est la présence d'un composant dans l'inventaire courant d'une référence.
type Usage struct {
	ComponentID uuid.UUID
	Version     string
	PURL        string
	ProjectID   uuid.UUID
	ProjectSlug string
	ProjectName string
	ProjectKind string
	RefID       uuid.UUID
	RefKind     string
	RefName     string
	Origin      sbom.Origin
	Confidence  *float64
	Licenses    []string
	SnapshotID  uuid.UUID
	ScannedAt   time.Time
	Commit      string
}

// ComponentUsage renvoie les références dont l'inventaire courant contient un composant
// de base purlBase (toutes versions), du plus récent instantané au plus ancien
// (UsageMax au plus). Références retirées et projets archivés exclus.
func ComponentUsage(ctx context.Context, tx *db.OrgTx, purlBase string) ([]Usage, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.version, c.purl, p.id, p.slug, p.name, p.kind, r.id, r.kind, r.name, i.origin, i.confidence, i.licenses,
		       s.id, s.scanned_at, coalesce(s.commit_sha, '')
		  FROM components c
		  JOIN component_set_items i ON i.org_id = c.org_id AND i.component_id = c.id
		  JOIN ref_current rc ON rc.org_id = i.org_id AND rc.set_id = i.set_id
		  JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id AND r.removed_at IS NULL
		  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id AND p.archived_at IS NULL
		  JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id
		 WHERE c.purl_base = $1
		 ORDER BY s.scanned_at DESC, p.name, r.name, c.version
		 LIMIT `+strconv.Itoa(UsageMax), purlBase)
	if err != nil {
		return nil, wrap("usages d'un composant", err)
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		var origin string
		var conf sql.NullFloat64
		if err := rows.Scan(&u.ComponentID, &u.Version, &u.PURL, &u.ProjectID, &u.ProjectSlug, &u.ProjectName, &u.ProjectKind,
			&u.RefID, &u.RefKind, &u.RefName, &origin, &conf, db.Array(&u.Licenses), &u.SnapshotID, &u.ScannedAt, &u.Commit); err != nil {
			return nil, wrap("usages d'un composant", err)
		}
		u.Origin = sbom.Origin(origin)
		if conf.Valid {
			f := conf.Float64
			u.Confidence = &f
		}
		u.ScannedAt = u.ScannedAt.UTC()
		out = append(out, u)
	}
	return out, wrap("usages d'un composant", rows.Err())
}

// Component renvoie le composant id et l'usage courant de sa famille (même purl_base).
func (s *Service) Component(ctx context.Context, org tenant.OrgID, id uuid.UUID) (c Component, usage []Usage, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		if c, err = GetComponent(ctx, tx, id); err != nil {
			return err
		}
		usage, err = ComponentUsage(ctx, tx, c.PURLBase)
		return err
	})
	return c, usage, err
}
