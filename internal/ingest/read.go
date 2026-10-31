package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/syft"
	"leblanc.io/lotor/internal/tenant"
)

// Get renvoie l'ingestion id si elle a été envoyée par agentID ; ErrNotFound sinon.
func (s *Service) Get(ctx context.Context, org tenant.OrgID, agentID, id uuid.UUID) (Ingestion, error) {
	var in Ingestion
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		in, err = scanIngestion(tx.QueryRowContext(ctx, `SELECT `+ingestionColumns+` FROM ingestions WHERE id = $1 AND agent_id = $2`,
			id, agentID))
		return err
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return Ingestion{}, ErrNotFound
	}
	return in, wrap("lecture d'une ingestion", err)
}

// RecentPageMax borne Recent.
const RecentPageMax = 50

// Recent renvoie les dernières ingestions d'un projet, des plus récentes aux plus
// anciennes.
func (s *Service) Recent(ctx context.Context, org tenant.OrgID, projectID uuid.UUID, limit int) ([]Ingestion, error) {
	if limit < 1 || limit > RecentPageMax {
		return nil, fmt.Errorf("ingest: taille de liste %d hors de [1, %d]", limit, RecentPageMax)
	}
	var out []Ingestion
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+ingestionColumns+` FROM ingestions WHERE project_id = $1
			ORDER BY received_at DESC, id DESC LIMIT $2`, projectID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			in, err := scanIngestion(rows)
			if err != nil {
				return err
			}
			out = append(out, in)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("ingestions récentes", err)
}

// Export renvoie le SBOM blobID (format d'origine format) réencodé en target. Le
// réencodage passe par Syft (sbom/syft.Encode) ; un identifiant de licence plus récent que
// le schéma de CycloneDX 1.6 y est écrit en nom, pour que le document reste valide.
func (s *Service) Export(ctx context.Context, org tenant.OrgID, blobID uuid.UUID, format sbom.Format, target syft.Target) ([]byte, error) {
	data, err := s.Blob(ctx, org, blobID)
	if err != nil {
		return nil, err
	}
	// syft.Encode ne prend pas de contexte : un client parti n'engage pas le calcul.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := syft.Encode(&buf, format, data, target, s.validator.CycloneDXLicenseIDs("1.6")); err != nil {
		return nil, fmt.Errorf("ingest: réencodage en %s : %w", target, err)
	}
	return buf.Bytes(), nil
}

// Blob renvoie le SBOM blobID décompressé (le JSON tel que reçu).
func (s *Service) Blob(ctx context.Context, org tenant.OrgID, blobID uuid.UUID) ([]byte, error) {
	var gz []byte
	var size int64
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT content, size FROM sbom_blobs WHERE id = $1`, blobID).Scan(&gz, &size)
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, wrap("lecture d'un SBOM", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("ingest: SBOM stocké illisible : %w", err)
	}
	out := bytes.NewBuffer(make([]byte, 0, size))
	if _, err := io.Copy(out, io.LimitReader(zr, size+1)); err != nil {
		return nil, fmt.Errorf("ingest: SBOM stocké illisible : %w", err)
	}
	if int64(out.Len()) != size {
		return nil, fmt.Errorf("ingest: SBOM stocké de %d octets au lieu de %d", out.Len(), size)
	}
	return out.Bytes(), nil
}
