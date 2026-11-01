//go:build integration

package org_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"testing/fstest"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/db/migrations"
)

// migrationsBefore renvoie les migrations du projet antérieures à celle dont le nom finit
// par suffix (repérée par son sujet, pas par son numéro, qui peut changer avant la
// publication).
func migrationsBefore(t *testing.T, suffix string) fstest.MapFS {
	t.Helper()
	all, err := db.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{}
	for _, m := range all {
		if strings.HasSuffix(m.Name, suffix) {
			return fsys
		}
		fsys[m.Name] = &fstest.MapFile{Data: []byte(m.SQL)}
	}
	t.Fatalf("migration *%s introuvable", suffix)
	return nil
}

// TestTeamsMigrationKeepsEveryoneTheirAccess : la migration des équipes crée une équipe
// « Général » par organisation (« General » en anglais), y rattache les projets, les
// jetons d'inscription et les agents serveur, y fait entrer chaque membre avec son rôle
// (viewer → reader), puis réduit le rôle d'organisation à member ou admin.
func TestTeamsMigrationKeepsEveryoneTheirAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t, dbtest.WithoutMigrations())
	owner := tdb.Owner(t)
	if _, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole, Migrations: migrationsBefore(t, "_teams.sql")}); err != nil {
		t.Fatal(err)
	}
	const fr, en = "0192d6a4-0000-7000-8000-000000000001", "0192d6a4-0000-7000-8000-000000000002"
	seed := []string{
		`INSERT INTO users (id, email, password_hash) VALUES (1, 'alice@example.org', 'x'), (2, 'bob@example.org', 'x'),
		        (3, 'carl@example.org', 'x')`,
		`INSERT INTO organizations (id, slug, name, default_language) VALUES ('` + fr + `', 'nord', 'Nord', 'fr'),
		        ('` + en + `', 'sud', 'Sud', 'en')`,
		`INSERT INTO org_memberships (org_id, user_id, role) VALUES ('` + fr + `', 1, 'admin'), ('` + fr + `', 2, 'viewer'),
		        ('` + fr + `', 3, 'analyst'), ('` + en + `', 2, 'admin')`,
		`INSERT INTO agents (org_id, id, kind, name) VALUES ('` + fr + `', '0192d6a4-0000-7000-8000-0000000000a1', 'host', 'srv'),
		        ('` + fr + `', '0192d6a4-0000-7000-8000-0000000000a2', 'repo', 'ci')`,
		`INSERT INTO projects (org_id, id, kind, slug, name, agent_id) VALUES
		        ('` + fr + `', '0192d6a4-0000-7000-8000-0000000000b1', 'host', 'srv', 'srv', '0192d6a4-0000-7000-8000-0000000000a1'),
		        ('` + fr + `', '0192d6a4-0000-7000-8000-0000000000b2', 'repo', 'web', 'web', '0192d6a4-0000-7000-8000-0000000000a2'),
		        ('` + en + `', '0192d6a4-0000-7000-8000-0000000000b3', 'repo', 'api', 'api', NULL)`,
		`INSERT INTO enrollment_tokens (org_id, id, public_id, secret_hash, name, expires_at, max_uses)
		        VALUES ('` + fr + `', '0192d6a4-0000-7000-8000-0000000000c1', 'aaaaaaaaaaaaaaaaaaaaaaaaaa', sha256('e'::bytea), 'parc',
		                now() + interval '1 day', 5)`,
	}
	for _, q := range seed {
		if _, err := owner.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	if _, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: tdb.AppRole}); err != nil {
		t.Fatal(err)
	}

	teamOf := func(org, name string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `SELECT id FROM teams WHERE org_id = $1 AND name = $2`, org, name).Scan(&id); err != nil {
			t.Fatalf("équipe %s de %s : %v", name, org, err)
		}
		return id
	}
	general, sud := teamOf(fr, "Général"), teamOf(en, "General")
	var teams int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM teams`).Scan(&teams); err != nil || teams != 2 {
		t.Fatalf("%d équipes, %v", teams, err)
	}
	rows, err := owner.QueryContext(ctx, `SELECT m.org_id, m.user_id, m.role, t.team_id, t.role
		  FROM org_memberships m JOIN team_members t ON t.org_id = m.org_id AND t.user_id = m.user_id ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type member struct{ org, orgRole, team, teamRole string }
	got := map[int64][]member{}
	for rows.Next() {
		var m member
		var user int64
		if err := rows.Scan(&m.org, &user, &m.orgRole, &m.team, &m.teamRole); err != nil {
			t.Fatal(err)
		}
		got[user] = append(got[user], m)
	}
	want := map[int64][]member{
		1: {{fr, "admin", general, "admin"}},
		2: {{fr, "member", general, "reader"}, {en, "admin", sud, "admin"}},
		3: {{fr, "member", general, "analyst"}},
	}
	for user, w := range want {
		g := got[user]
		if len(g) != len(w) {
			t.Fatalf("compte %d : %+v, attendu %+v", user, g, w)
		}
		for i := range w {
			if g[i] != w[i] {
				t.Errorf("compte %d : %+v, attendu %+v", user, g[i], w[i])
			}
		}
	}
	check := func(query, want string) {
		t.Helper()
		var v sql.NullString
		if err := owner.QueryRowContext(ctx, query).Scan(&v); err != nil {
			t.Fatalf("%s : %v", query, err)
		}
		if v.String != want {
			t.Errorf("%s : %q, attendu %q", query, v.String, want)
		}
	}
	check(`SELECT team_id::text FROM projects WHERE slug = 'srv'`, general)
	check(`SELECT team_id::text FROM projects WHERE slug = 'web'`, general)
	check(`SELECT team_id::text FROM projects WHERE slug = 'api'`, sud)
	check(`SELECT team_id::text FROM agents WHERE name = 'srv'`, general)
	check(`SELECT team_id::text FROM agents WHERE name = 'ci'`, "")
	check(`SELECT team_id::text FROM enrollment_tokens WHERE name = 'parc'`, general)
	if _, err := owner.ExecContext(ctx, `UPDATE org_memberships SET role = 'viewer' WHERE user_id = 2`); err == nil {
		t.Error("rôle d'organisation viewer encore accepté")
	}
}
