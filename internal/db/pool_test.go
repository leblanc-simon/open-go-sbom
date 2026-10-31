package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"leblanc.io/open-go-sbom/internal/tenant"
)

func TestOpenHidesDSN(t *testing.T) {
	_, err := Open("postgres://user:s3cret@host:notaport/db", PoolConfig{})
	if err == nil {
		t.Fatal("DSN invalide accepté")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("le mot de passe fuit dans l'erreur : %v", err)
	}
}

func TestRoleFromDSN(t *testing.T) {
	cases := map[string]string{
		"postgres://ogsbom_app:pwd@localhost:5432/ogsbom": "ogsbom_app",
		"host=localhost user=ogsbom_app dbname=ogsbom":    "ogsbom_app",
		"postgres://%22weird%20name%22@localhost/ogsbom":  `"weird name"`,
	}
	for dsn, want := range cases {
		got, err := RoleFromDSN(dsn)
		if err != nil || got != want {
			t.Errorf("RoleFromDSN(%q) = %q, %v", dsn, got, err)
		}
	}
	if _, err := RoleFromDSN("postgres://host:bad/db"); err == nil {
		t.Error("DSN invalide accepté")
	}
}

func TestWaitReadyGivesUp(t *testing.T) {
	// Port 1 : rien n'y écoute, la connexion est refusée tout de suite.
	pool, err := Open("postgres://u:p@127.0.0.1:1/db?connect_timeout=1", PoolConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	start := time.Now()
	err = WaitReady(context.Background(), pool, 600*time.Millisecond, nil)
	if err == nil {
		t.Fatal("base injoignable considérée comme prête")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("attente de %s, bornée à 600 ms", elapsed)
	}
}

func TestInOrgRefusesZeroOrg(t *testing.T) {
	p := NewPool(nil)
	called := false
	err := p.InOrg(context.Background(), tenant.OrgID{}, func(*OrgTx) error { called = true; return nil })
	if !errors.Is(err, tenant.ErrZeroOrgID) || called {
		t.Fatalf("err = %v, fn appelée : %v", err, called)
	}
}
