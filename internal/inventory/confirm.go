package inventory

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
)

// Confirm traite le compte rendu d'un scan d'hôte ou de conteneur sans changement (signal
// de vie ou signalement des conteneurs de l'agent serveur) : si fingerprint est
// l'empreinte de l'ensemble courant de la référence d'hôte ou de conteneur refID, la date de dernière analyse de l'instantané courant avance comme pour un
// envoi identique, et Confirm renvoie true. Sinon (pas encore d'instantané, autre
// ensemble, référence de dépôt), rien n'est écrit : l'agent doit envoyer son SBOM. La
// référence est verrouillée comme par Store, si bien qu'un compte rendu et une ingestion
// de la même référence se succèdent.
func Confirm(ctx context.Context, tx *db.OrgTx, refID uuid.UUID, fingerprint [32]byte, scannedAt, now time.Time) (bool, error) {
	var refKind string
	err := tx.QueryRowContext(ctx, `SELECT kind FROM tracked_refs WHERE id = $1 FOR UPDATE`, refID).Scan(&refKind)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, wrap("verrou de la référence", err)
	}
	if !machineRef(refKind) {
		return false, nil
	}
	var snapshotID uuid.UUID
	var current []byte
	err = tx.QueryRowContext(ctx, `
		SELECT rc.snapshot_id, cs.fingerprint FROM ref_current rc
		  JOIN component_sets cs ON cs.org_id = rc.org_id AND cs.id = rc.set_id
		 WHERE rc.ref_id = $1`, refID).Scan(&snapshotID, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrap("état courant", err)
	}
	if !bytes.Equal(current, fingerprint[:]) {
		return false, nil
	}
	return true, wrap("date de dernière analyse", touch(ctx, tx, snapshotID, scannedAt, now))
}
