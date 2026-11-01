//go:build integration

package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/sbom"
)

// container crée un conteneur de l'hôte de la fixture, archivé à archived (nil : actif) ;
// absent dit si l'archivage vient de l'absence. Il renvoie le projet et sa référence.
func (f fixture) container(t *testing.T, key string, archived *time.Time, absent bool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	id, ref := newID(), newID()
	f.exec(t, `INSERT INTO projects (org_id, id, kind, slug, name, team_id, parent_id, parent_kind, container_key, container, seen_at,
		archived_at, archived_absent) VALUES ($1, $2, 'container', $3, $3, $1, $4, 'host', $3, '{}', $5, $6, $7)`,
		f.org, id, "srv-"+key, f.host, time.Now().Add(-400*24*time.Hour), archived, absent)
	f.exec(t, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'container', 'container', $4)`,
		f.org, ref, id, key)
	return id, ref
}

// storeContainer range un instantané du conteneur, avec un inventaire qui lui est propre.
func (f fixture) storeContainer(t *testing.T, project, ref uuid.UUID, pkg string, at time.Time) Result {
	t.Helper()
	return f.store(t, Record{ProjectID: project, RefID: ref, ScannedAt: at, BlobID: f.newBlob(t), Format: sbom.FormatSyft,
		SpecVersion: "16.1.11", Components: inventoryOf(pkg)})
}

// TestRetentionPurgesLongArchivedContainers (T18) : la rétention supprime, avec tout son
// historique, le projet d'un conteneur archivé pour absence depuis plus de
// ContainerPurgeAfter, et le journalise ; elle garde un conteneur archivé depuis moins
// longtemps, archivé à la main, portant une décision de triage, ou actif.
func TestRetentionPurgesLongArchivedContainers(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	f := newFixture(t, d.App)
	now := time.Now().UTC()
	at := func(days int) *time.Time { v := now.Add(-time.Duration(days) * 24 * time.Hour); return &v }

	old, oldRef := f.container(t, "ephemere", at(200), true)
	res := f.storeContainer(t, old, oldRef, "seul-ici@1.0.0", now.Add(-210*24*time.Hour))
	f.storeContainer(t, old, oldRef, "seul-ici@1.0.1", now.Add(-205*24*time.Hour))
	// Réception récente (dans la fenêtre) : seule la purge la supprime.
	f.exec(t, `INSERT INTO ingestions (org_id, id, agent_id, project_id, ref_id, scanned_at, blob_id, status, snapshot_id,
		outcome, received_at, finished_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'done', $8, 'unchanged', $6, $6)`,
		f.org, newID(), f.agent, old, oldRef, now.Add(-24*time.Hour), f.blob, res.SnapshotID)
	// Un constat et son historique, et une violation de politique qui le vise.
	f.exec(t, `INSERT INTO vulnerabilities (id, source_rank, severity, vulndb_built, updated_at) VALUES ('CVE-2099-0001', 0, 'high', now(), now()) ON CONFLICT DO NOTHING`)
	findingID := newID()
	f.exec(t, `INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status, severity, risk, fix_state,
		match_type, first_seen_at, last_seen_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
		SELECT $1, $2, $3, $4, i.component_id, 'CVE-2099-0001', 'open', 'high', 50, 'unknown', 'exact-direct', $5, $5, $6, $2, $5, $5
		  FROM component_set_items i WHERE i.set_id = $7 LIMIT 1`, f.org, findingID, old, oldRef, now, res.SnapshotID, res.SetID)
	f.exec(t, `INSERT INTO finding_events (org_id, finding_id, at, kind, snapshot_id, vulndb_archive) VALUES ($1, $2, $3, 'opened', $4, $2)`,
		f.org, findingID, now, res.SnapshotID)
	recent, recentRef := f.container(t, "recent", at(30), true)
	f.storeContainer(t, recent, recentRef, "recent@1.0.0", now.Add(-40*24*time.Hour))
	manual, _ := f.container(t, "manuel", at(300), false)
	triaged, _ := f.container(t, "trie", at(300), true)
	f.exec(t, `INSERT INTO triage_decisions (org_id, id, scope, project_id, vuln_id, purl, purl_base, action, status,
		author_label, created_at) VALUES ($1, $2, 'project', $3, 'CVE-2021-44228', 'pkg:npm/a@1', 'pkg:npm/a', 'set', 'affected',
		'analyste@example.org', now())`, f.org, newID(), triaged)
	active, _ := f.container(t, "actif", nil, false)

	policy := DefaultRetention()
	policy.ContainerPurgeAfter = 180 * 24 * time.Hour
	h := newHistory(t, d.App, policy, now)
	rep, err := h.Retain(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Containers != 1 {
		t.Fatalf("conteneurs purgés : %d, attendu 1", rep.Containers)
	}
	for table, q := range map[string]string{
		"projet":      `SELECT count(*) FROM projects WHERE id = $1`,
		"références":  `SELECT count(*) FROM tracked_refs WHERE project_id = $1`,
		"instantanés": `SELECT count(*) FROM snapshots WHERE project_id = $1`,
		"réceptions":  `SELECT count(*) FROM ingestions WHERE project_id = $1`,
		"courant":     `SELECT count(*) FROM ref_current WHERE project_id = $1`,
		"constats":    `SELECT count(*) FROM findings WHERE project_id = $1`,
	} {
		if n := f.count(t, q, old); n != 0 {
			t.Errorf("%s du conteneur purgé : %d", table, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM component_sets WHERE id = $1`, res.SetID); n != 0 {
		t.Errorf("ensemble devenu orphelin gardé : %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_events WHERE action = 'project.purged' AND target_id = $1
		AND details->>'reason' = 'archived_absent' AND details->>'host' = 'srv'`, old.String()); n != 1 {
		t.Errorf("événement project.purged : %d", n)
	}
	for name, id := range map[string]uuid.UUID{"récent": recent, "manuel": manual, "trié": triaged, "actif": active, "hôte": f.host} {
		if n := f.count(t, `SELECT count(*) FROM projects WHERE id = $1`, id); n != 1 {
			t.Errorf("projet %s supprimé", name)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM snapshots WHERE project_id = $1`, recent); n != 1 {
		t.Errorf("historique du conteneur récent : %d instantanés", n)
	}
	// Idempotent.
	if rep, err := h.Retain(context.Background(), f.org); err != nil || rep.Containers != 0 {
		t.Fatalf("second passage : %d, %v", rep.Containers, err)
	}
	// Sans purge (0), rien n'est supprimé.
	f.exec(t, `UPDATE projects SET archived_at = $2, archived_absent = true WHERE id = $1`, recent, at(400))
	off := DefaultRetention()
	if rep, err := newHistory(t, d.App, off, now).Retain(context.Background(), f.org); err != nil || rep.Containers != 0 {
		t.Fatalf("purge désactivée : %d, %v", rep.Containers, err)
	}
}

func TestContainerPurgeAfterRespectsTheWindow(t *testing.T) {
	p := DefaultRetention()
	p.ContainerPurgeAfter = 30 * 24 * time.Hour
	if err := p.Validate(); err == nil {
		t.Fatal("purge sous la fenêtre de 90 jours acceptée")
	}
	p.ContainerPurgeAfter = 90 * 24 * time.Hour
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
