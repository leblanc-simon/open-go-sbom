//go:build integration

package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/sbom"
)

func (f fixture) confirm(t *testing.T, fp [32]byte, ref uuid.UUID, at time.Time) bool {
	t.Helper()
	var ok bool
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		var err error
		ok, err = Confirm(context.Background(), tx, ref, fp, at, time.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestConfirmAdvancesHostLastScan : un compte rendu dont l'empreinte est celle de
// l'ensemble courant avance la date de dernière analyse comme un envoi identique, sans
// nouvel instantané ni analyse ; sinon rien n'est écrit.
func TestConfirmAdvancesHostLastScan(t *testing.T) {
	t.Parallel()
	f := newFixture(t, newDB(t).App)
	cs := components(3, "1.0.0")
	fp := sbom.Fingerprint(cs)
	t0 := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Microsecond)
	if f.confirm(t, fp, f.hostRef, t0) {
		t.Fatal("confirmé sans instantané")
	}
	first := f.store(t, f.hostRecord(cs, t0))
	jobs := f.analysisJobs(t, f.hostRef)
	if !f.confirm(t, fp, f.hostRef, t0.Add(24*time.Hour)) {
		t.Fatal("même empreinte non confirmée")
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE id = $1 AND last_scanned_at = $2 AND scanned_at = $3`,
		first.SnapshotID, t0.Add(24*time.Hour), t0); n != 1 {
		t.Error("date de dernière analyse non avancée")
	}
	if !f.confirm(t, fp, f.hostRef, t0.Add(time.Hour)) {
		t.Fatal("confirmation plus ancienne")
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE last_scanned_at = $1`, t0.Add(24*time.Hour)); n != 1 {
		t.Error("date de dernière analyse reculée")
	}
	if f.confirm(t, sbom.Fingerprint(components(4, "1.0.0")), f.hostRef, t0.Add(25*time.Hour)) {
		t.Error("autre empreinte confirmée")
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE ref_id = $1`, f.hostRef); n != 1 || f.analysisJobs(t, f.hostRef) != jobs {
		t.Errorf("%d instantanés, analyses %d → %d", n, jobs, f.analysisJobs(t, f.hostRef))
	}

	// Une référence de dépôt n'est jamais confirmée ainsi ; une référence inconnue est
	// signalée.
	f.store(t, f.repoRecord(commit(1), cs, t0))
	if f.confirm(t, fp, f.main, t0.Add(time.Hour)) {
		t.Error("référence de dépôt confirmée")
	}
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		_, err := Confirm(context.Background(), tx, newID(), fp, t0, time.Now())
		return err
	})
	if err != ErrNotFound {
		t.Errorf("référence inconnue : %v", err)
	}
}
