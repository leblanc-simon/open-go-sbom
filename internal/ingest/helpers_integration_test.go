//go:build integration

package ingest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/schema"
	"leblanc.io/lotor/internal/tenant"
)

var (
	validatorOnce sync.Once
	validator     *schema.Validator
	validatorErr  error
)

func testValidator(t testing.TB) *schema.Validator {
	t.Helper()
	validatorOnce.Do(func() { validator, validatorErr = schema.New() })
	if validatorErr != nil {
		t.Fatal(validatorErr)
	}
	return validator
}

var testLimits = Limits{MaxUpload: 8 << 20, SBOM: sbom.Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxComponents: 20_000}}

func newService(t testing.TB, pool *db.Pool, limits Limits) *Service {
	t.Helper()
	s, err := NewService(Options{Pool: pool, Validator: testValidator(t), Limits: limits,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fixture : une organisation, un agent dépôt à qui le dépôt « depot » (branche main) est
// confié, un dépôt « autre » qui ne lui est pas confié, un agent serveur et son hôte.
type fixture struct {
	pool      *db.Pool
	org       tenant.OrgID
	repoAgent uuid.UUID
	hostAgent uuid.UUID
	repo      uuid.UUID
	other     uuid.UUID
	host      uuid.UUID
	hostName  string
}

func newID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func newFixture(t testing.TB, pool *db.Pool) fixture {
	t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(org.String()[24:], "-", "")
	f := fixture{pool: pool, org: org, repoAgent: newID(), hostAgent: newID(), repo: newID(), other: newID(), host: newID(),
		hostName: "srv-" + suffix}
	f.exec(t, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'Org', 'fr')`, org, "o-"+suffix)
	f.exec(t, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', 'depot'), ($1, $3, 'host', $4)`,
		org, f.repoAgent, f.hostAgent, f.hostName)
	f.exec(t, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id) VALUES
		($1, $2, 'repo', 'depot', 'Dépôt', $3), ($1, $4, 'repo', 'autre', 'Autre', NULL), ($1, $5, 'host', 'srv', 'srv', $6)`,
		org, f.repo, f.repoAgent, f.other, f.host, f.hostAgent)
	f.exec(t, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES
		($1, $2, $3, 'repo', 'branch', 'main'), ($1, $4, $5, 'repo', 'branch', 'main'), ($1, $6, $7, 'host', 'host', $8)`,
		org, newID(), f.repo, newID(), f.other, newID(), f.host, f.hostName)
	return f
}

func (f fixture) exec(t testing.TB, query string, args ...any) {
	t.Helper()
	err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s : %v", query, err)
	}
}

func (f fixture) count(t testing.TB, query string, args ...any) int {
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

func commit(n int) string { return fmt.Sprintf("%040x", n) }

func (f fixture) repoContext(n int) Context {
	return Context{ProjectID: f.repo, RefKind: project.RefBranch, RefName: "main", Commit: commit(n), AgentVersion: "1.0.0",
		ScannedAt: time.Now().Add(-time.Hour + time.Duration(n)*time.Second)}
}

func (f fixture) hostContext(at time.Time) Context {
	return Context{ProjectID: f.host, RefKind: project.RefHost, RefName: f.hostName, AgentVersion: "0.9.0", ScannedAt: at}
}

func testdata(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/sbom", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// receive envoie un SBOM et décode l'ingestion comme le ferait le job.
func receive(t testing.TB, s *Service, f fixture, agent uuid.UUID, c Context, data []byte) Ingestion {
	t.Helper()
	in, err := s.Receive(context.Background(), f.org, agent, c, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if in.Status == StatusQueued {
		if err := s.Decode(context.Background(), f.org, in.ID); err != nil {
			t.Fatal(err)
		}
		if in, err = s.Get(context.Background(), f.org, agent, in.ID); err != nil {
			t.Fatal(err)
		}
	}
	return in
}

// syntheticCycloneDX construit un SBOM CycloneDX 1.6 de n composants npm.
func syntheticCycloneDX(n int, serial string) []byte {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"urn:uuid:` + serial + `",` +
		`"metadata":{"timestamp":"2026-10-31T00:00:00Z"},"components":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"bom-ref":"c%[1]d","type":"library","name":"paquet-%05[1]d","version":"1.%[1]d.0",`+
			`"purl":"pkg:npm/paquet-%05[1]d@1.%[1]d.0","licenses":[{"license":{"id":"MIT"}}],`+
			`"cpe":"cpe:2.3:a:paquet-%05[1]d:paquet-%05[1]d:1.%[1]d.0:*:*:*:*:*:*:*"}`, i)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func newDB(t testing.TB) *dbtest.DB { return dbtest.New(t) }
