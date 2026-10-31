package db

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"leblanc.io/open-go-sbom/internal/db/migrations"
)

func TestEmbeddedMigrationsAreWellFormed(t *testing.T) {
	all, err := LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 || all[0].Name != "001_init.sql" {
		t.Fatalf("migrations embarquées = %v", all)
	}
	for _, m := range all {
		if len(m.Checksum) != 64 || m.SQL == "" {
			t.Errorf("%s : somme %q, %d octets", m.Name, m.Checksum, len(m.SQL))
		}
	}
}

func TestLoadMigrationsRejectsBadNames(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"nom sans numéro":     {"init.sql": {Data: []byte("SELECT 1")}},
		"numéro à 2 chiffres": {"01_init.sql": {Data: []byte("SELECT 1")}},
		"majuscules":          {"001_Init.sql": {Data: []byte("SELECT 1")}},
		"trou":                {"001_a.sql": {Data: []byte("SELECT 1")}, "003_c.sql": {Data: []byte("SELECT 1")}},
		"doublon":             {"001_a.sql": {Data: []byte("SELECT 1")}, "001_b.sql": {Data: []byte("SELECT 1")}},
		"ne commence pas à 1": {"002_a.sql": {Data: []byte("SELECT 1")}},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadMigrations(fsys); err == nil {
				t.Fatal("accepté")
			}
		})
	}
}

func TestLoadMigrationsIgnoresOtherFiles(t *testing.T) {
	got, err := LoadMigrations(fstest.MapFS{
		"001_a.sql": {Data: []byte("SELECT 1")},
		"002_b.sql": {Data: []byte("SELECT 2")},
		"README.md": {Data: []byte("doc")},
		"embed.go":  {Data: []byte("package migrations")},
		"sub/x.sql": {Data: []byte("SELECT 3")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Version != 1 || got[1].Name != "002_b.sql" {
		t.Fatalf("migrations = %+v", got)
	}
}

func TestPendingMigrations(t *testing.T) {
	all := []Migration{{Version: 1, Name: "001_a.sql", Checksum: "aa"}, {Version: 2, Name: "002_b.sql", Checksum: "bb"}}

	pending, err := pendingMigrations(all, map[int]appliedMigration{1: {"001_a.sql", "aa"}})
	if err != nil || len(pending) != 1 || pending[0].Version != 2 {
		t.Fatalf("pending = %v, %v", pending, err)
	}

	_, err = pendingMigrations(all, map[int]appliedMigration{1: {"001_a.sql", "ff"}})
	if !errors.Is(err, ErrChecksumMismatch) || !strings.Contains(err.Error(), "001_a.sql") {
		t.Fatalf("somme modifiée : err = %v", err)
	}

	_, err = pendingMigrations(all, map[int]appliedMigration{1: {"001_renamed.sql", "aa"}})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("migration renommée : err = %v", err)
	}

	_, err = pendingMigrations(all, map[int]appliedMigration{3: {"003_future.sql", "cc"}})
	if !errors.Is(err, ErrUnknownMigration) || !strings.Contains(err.Error(), "003_future.sql") {
		t.Fatalf("base plus récente : err = %v", err)
	}
}
