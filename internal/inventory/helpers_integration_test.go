//go:build integration

package inventory

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
)

// fixture est une organisation avec un agent, un dépôt (branche main) et un hôte.
type fixture struct {
	pool    *db.Pool
	org     tenant.OrgID
	agent   uuid.UUID
	repo    uuid.UUID
	main    uuid.UUID
	host    uuid.UUID
	hostRef uuid.UUID
	blob    uuid.UUID
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func newFixture(t *testing.T, pool *db.Pool) fixture {
	t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{pool: pool, org: org, agent: newID(), repo: newID(), main: newID(), host: newID(), hostRef: newID(), blob: newID()}
	suffix := strings.ReplaceAll(org.String()[24:], "-", "")
	f.exec(t,
		`WITH o AS (INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'Org', 'fr') RETURNING id) INSERT INTO teams (org_id, id, name) SELECT id, id, 'Général' FROM o`, org, "o-"+suffix)
	f.exec(t, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'agent')`, org, f.agent)
	f.exec(t, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id, team_id) VALUES ($1, $2, 'repo', 'depot', 'Dépôt', $3, $1)`, org, f.repo, f.agent)
	f.exec(t, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`, org, f.main, f.repo)
	f.exec(t, `INSERT INTO projects (org_id, id, kind, slug, name, team_id) VALUES ($1, $2, 'host', 'srv', 'srv', $1)`, org, f.host)
	f.exec(t, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'host', 'host', $4)`,
		org, f.hostRef, f.host, "srv-"+suffix)
	f.exec(t, `INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content) VALUES ($1, $2, sha256($3::bytea), 2, 1, '\x00'::bytea)`,
		org, f.blob, []byte(org.String()))
	return f
}

func (f fixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s : %v", query, err)
	}
}

func (f fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("%s : %v", query, err)
	}
	return n
}

// components construit un inventaire normalisé de n paquets npm, version v.
func components(n int, v string) []sbom.Component {
	raw := sbom.RawDocument{Format: sbom.FormatCycloneDX, SpecVersion: "1.6"}
	for i := range n {
		raw.Components = append(raw.Components, sbom.RawComponent{
			PURL: fmt.Sprintf("pkg:npm/paquet-%05d@%s", i, v), Licenses: []string{"MIT"},
			CPEs: []string{fmt.Sprintf("cpe:2.3:a:p:paquet-%05d:%s:*:*:*:*:*:*:*", i, v)},
		})
	}
	return sbom.Normalize(raw).Components
}

func (f fixture) repoRecord(commit string, cs []sbom.Component, scanned time.Time) Record {
	return Record{ProjectID: f.repo, RefID: f.main, Commit: commit, AgentID: f.agent, AgentVersion: "1.0.0",
		ScannedAt: scanned, BlobID: f.blob, Format: sbom.FormatCycloneDX, SpecVersion: "1.6", Components: cs}
}

func (f fixture) hostRecord(cs []sbom.Component, scanned time.Time) Record {
	return Record{ProjectID: f.host, RefID: f.hostRef, ScannedAt: scanned, BlobID: f.blob,
		Format: sbom.FormatSyft, SpecVersion: "16.1.11", Components: cs}
}

func (f fixture) store(t *testing.T, r Record) Result {
	t.Helper()
	var res Result
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		var err error
		res, err = Store(context.Background(), tx, r, time.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func commit(n int) string { return fmt.Sprintf("%040x", n) }

func newDB(t *testing.T) *dbtest.DB { return dbtest.New(t) }
