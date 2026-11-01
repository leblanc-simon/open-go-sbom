package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/syft"
	"leblanc.io/lotor/internal/tenant"
)

// DecodeHandler est le handler du job DecodeKind. Il est idempotent : une ingestion
// terminée (done ou failed) n'est plus touchée, et la fin d'une ingestion revérifie son
// état sous verrou dans la transaction qui range l'inventaire.
func (s *Service) DecodeHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p DecodePayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		return s.Decode(ctx, e.OrgID, p.IngestionID)
	})
}

// pending est une ingestion à décoder.
type pending struct {
	agentID      uuid.UUID
	projectID    uuid.UUID
	refID        uuid.UUID
	commit       string
	agentVersion string
	scannedAt    time.Time
	blobID       uuid.UUID
}

// Decode décode l'ingestion id et range son inventaire (voir la documentation du paquet).
func (s *Service) Decode(ctx context.Context, org tenant.OrgID, id uuid.UUID) error {
	in, active, err := s.start(ctx, org, id)
	if err != nil || !active {
		return err
	}
	var content []byte
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT content FROM sbom_blobs WHERE id = $1`, in.blobID).Scan(&content)
	}, db.ReadOnly())
	if err != nil {
		return wrap("lecture du SBOM", err)
	}
	h, doc, err := s.decode(ctx, content)
	if err != nil {
		rej, ok := sbom.AsError(err)
		if !ok {
			return err
		}
		return s.fail(ctx, org, id, h, rej)
	}
	return s.finish(ctx, org, id, in, h, doc)
}

// start passe l'ingestion en cours de décodage ; active faux si elle est déjà terminée.
func (s *Service) start(ctx context.Context, org tenant.OrgID, id uuid.UUID) (pending, bool, error) {
	var in pending
	var status string
	var blob uuid.NullUUID
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT status, agent_id, project_id, ref_id, coalesce(commit_sha, ''), agent_version, scanned_at, blob_id
			  FROM ingestions WHERE id = $1 FOR UPDATE`, id).
			Scan(&status, &in.agentID, &in.projectID, &in.refID, &in.commit, &in.agentVersion, &in.scannedAt, &blob)
		if err != nil || (status != string(StatusQueued) && status != string(StatusProcessing)) {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE ingestions SET status = 'processing', started_at = coalesce(started_at, $2) WHERE id = $1`,
			id, s.now().UTC())
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		// Ingestion disparue (organisation supprimée) : rien à faire, ni à réessayer.
		return pending{}, false, jobs.Permanent(fmt.Errorf("%w : %s", ErrNotFound, id))
	}
	if err != nil {
		return pending{}, false, wrap("début du décodage", err)
	}
	in.blobID = blob.UUID
	return in, status == string(StatusQueued) || status == string(StatusProcessing), nil
}

// decode applique les bornes préalables en flux, la validation par schéma puis le
// décodage. Le JSON n'est gardé en mémoire que dans les bornes : Precheck s'arrête au
// premier dépassement, avant tout décodage complet.
//
// Le délai du job (ingest.decode_timeout) interrompt la lecture en flux de Precheck et
// est vérifié entre les étapes ; la validation et le décodage de Syft, linéaires en taille
// et sans contexte, vont au bout de l'étape commencée (SEC-11). Un dépassement n'est
// jamais un refus du document : le job échoue et sera réessayé.
func (s *Service) decode(ctx context.Context, gz []byte) (sbom.Header, sbom.Document, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return sbom.Header{}, sbom.Document{}, sbom.Reject(sbom.KeyMalformed, "", err)
	}
	var data bytes.Buffer
	h, err := sbom.Precheck(io.TeeReader(ctxReader{ctx: ctx, r: zr}, &data), s.limits.SBOM)
	if cerr := ctx.Err(); cerr != nil {
		return h, sbom.Document{}, cerr
	}
	if err != nil {
		return h, sbom.Document{}, err
	}
	if err := s.validator.Validate(h.Format, h.SpecVersion, data.Bytes()); err != nil {
		return h, sbom.Document{}, err
	}
	if err := ctx.Err(); err != nil {
		return h, sbom.Document{}, err
	}
	doc, err := syft.Decode(h.Format, data.Bytes())
	if cerr := ctx.Err(); cerr != nil {
		return h, sbom.Document{}, cerr
	}
	return h, doc, err
}

// ctxReader interrompt une lecture dès que ctx est annulé.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// fail termine l'ingestion en échec, sans rien ranger.
func (s *Service) fail(ctx context.Context, org tenant.OrgID, id uuid.UUID, h sbom.Header, rej *sbom.Error) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE ingestions SET status = 'failed', error_key = $2, error_detail = $3, format = NULLIF($4, ''),
			       spec_version = NULLIF($5, ''), finished_at = $6
			 WHERE id = $1 AND status IN ('queued', 'processing')`,
			id, rej.Key, rej.Detail, string(h.Format), truncate(h.SpecVersion, 32), s.now().UTC())
		return err
	})
	if err != nil {
		return wrap("échec de l'ingestion", err)
	}
	s.logger.InfoContext(ctx, "ingestion refusée", "org", org.String(), "ingestion", id.String(), "key", rej.Key)
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// finish range l'inventaire et termine l'ingestion dans une seule transaction.
func (s *Service) finish(ctx context.Context, org tenant.OrgID, id uuid.UUID, in pending, h sbom.Header, doc sbom.Document) error {
	var res inventory.Result
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM ingestions WHERE id = $1 FOR UPDATE`, id).Scan(&status); err != nil {
			return err
		}
		if status != string(StatusProcessing) {
			// Terminée par une exécution concurrente (bail perdu puis repris).
			return nil
		}
		now := s.now().UTC()
		var err error
		res, err = inventory.Store(ctx, tx, inventory.Record{
			ProjectID: in.projectID, RefID: in.refID, Commit: in.commit, AgentID: in.agentID, AgentVersion: in.agentVersion,
			ScannedAt: in.scannedAt, BlobID: in.blobID, Format: doc.Format, SpecVersion: doc.SpecVersion, Components: doc.Components,
			Enrichment: doc.Enrichment, EnrichmentModel: doc.EnrichmentModel,
		}, now)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE ingestions SET status = 'done', format = $2, spec_version = $3, component_count = $4, skipped_count = $5,
			       snapshot_id = $6, outcome = $7, finished_at = $8
			 WHERE id = $1`,
			id, string(doc.Format), truncate(doc.SpecVersion, 32), len(doc.Components), doc.Skipped, res.SnapshotID, string(res.Outcome), now)
		return err
	})
	if err != nil {
		return wrap("rangement de l'inventaire", err)
	}
	s.logger.InfoContext(ctx, "ingestion terminée", "org", org.String(), "ingestion", id.String(),
		"components", len(doc.Components), "outcome", string(res.Outcome), "analysis", res.CurrentChanged)
	return nil
}
