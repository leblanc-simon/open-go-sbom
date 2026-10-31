//go:build integration

package account_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/token"
)

func tokenKey(err error) string {
	var te *account.TokenError
	if errors.As(err, &te) {
		return te.Key
	}
	return ""
}

// TestPersonalTokenLifecycle : création (secret montré une fois, haché en base), lecture,
// authentification, révocation immédiate, expiration, compte désactivé.
func TestPersonalTokenLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb, s := setup(t)
	u, _, err := s.Create(ctx, audit.System, "pat@example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := s.Create(ctx, audit.System, "autre@example.org", true)
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{UserID: u.ID, Email: u.Email}
	tok, issued, err := s.CreatePersonalToken(ctx, actor, u.ID, " CI nocturne ", 30)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "CI nocturne" || !strings.HasPrefix(issued.Plaintext, "ogsbom_pat_") || !strings.HasPrefix(tok.Prefix(), "ogsbom_pat_") {
		t.Fatalf("jeton : %+v %q", tok, issued.Plaintext)
	}
	// Seule l'empreinte est stockée : le secret n'apparaît nulle part en base.
	var stored int
	secret := issued.Plaintext[strings.LastIndexByte(issued.Plaintext, '_')+1:]
	if err := tdb.App.DB().QueryRowContext(ctx, `SELECT count(*) FROM personal_access_tokens WHERE secret_hash::text LIKE '%' || $1 || '%' OR name LIKE '%' || $1 || '%'`,
		secret).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("secret en base : %d, %v", stored, err)
	}

	p, err := s.AuthenticateToken(ctx, issued.Plaintext)
	if err != nil || p.UserID != u.ID || p.TokenID != tok.ID || p.RateKey() != "pat:"+tok.PublicID {
		t.Fatalf("authentification : %+v, %v", p, err)
	}
	list, err := s.PersonalTokens(ctx, u.ID)
	if err != nil || len(list) != 1 || list[0].LastUsedAt == nil || !list[0].Active(list[0].CreatedAt) {
		t.Fatalf("liste : %+v, %v", list, err)
	}

	// Refus avant vérification du secret : toujours la même clé.
	agentTok, _ := token.New(token.Agent)
	forged := issued.Plaintext[:len(issued.Plaintext)-4] + "aaaa"
	for name, raw := range map[string]string{"vide": "", "agent": agentTok.Plaintext, "secret faux": forged,
		"inconnu": mustPAT(t)} {
		if _, err := s.AuthenticateToken(ctx, raw); tokenKey(err) != account.KeyTokenInvalid {
			t.Errorf("%s : %v", name, err)
		}
	}

	// Un autre compte ne révoque pas ce jeton (il ne le voit pas).
	if err := s.RevokePersonalToken(ctx, audit.System, other.ID, tok.ID); !errors.Is(err, account.ErrTokenNotFound) {
		t.Fatalf("révocation par un autre compte : %v", err)
	}
	if err := s.RevokePersonalToken(ctx, actor, u.ID, tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePersonalToken(ctx, actor, u.ID, tok.ID); err != nil {
		t.Fatalf("seconde révocation : %v", err)
	}
	if _, err := s.AuthenticateToken(ctx, issued.Plaintext); tokenKey(err) != account.KeyTokenRevoked {
		t.Fatalf("jeton révoqué : %v", err)
	}
	if err := s.RevokePersonalToken(ctx, actor, u.ID, uuid.Must(uuid.NewV7())); !errors.Is(err, account.ErrTokenNotFound) {
		t.Fatalf("jeton inconnu : %v", err)
	}

	// Expiré.
	_, expiring, err := s.CreatePersonalToken(ctx, actor, u.ID, "court", 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tdb.Owner(t).ExecContext(ctx, `UPDATE personal_access_tokens SET created_at = now() - interval '9 days',
		expires_at = now() - interval '1 day' WHERE name = 'court'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateToken(ctx, expiring.Plaintext); tokenKey(err) != account.KeyTokenExpired {
		t.Fatalf("jeton expiré : %v", err)
	}

	// Compte désactivé : le jeton ne donne jamais plus que son propriétaire.
	_, live, err := s.CreatePersonalToken(ctx, actor, u.ID, "actif", 90)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetActive(ctx, audit.Actor{UserID: other.ID}, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateToken(ctx, live.Plaintext); tokenKey(err) != account.KeyAccountClosed {
		t.Fatalf("compte désactivé : %v", err)
	}

	// Journal de l'instance.
	page, err := audit.ListInstance(ctx, tdb.App.DB(), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	created, revoked := 0, 0
	for _, e := range page.Items {
		switch e.Action {
		case audit.PersonalTokenCreated:
			created++
		case audit.PersonalTokenRevoked:
			revoked++
		}
		if strings.Contains(e.Details["prefix"], secret) {
			t.Fatal("secret journalisé")
		}
	}
	if created != 3 || revoked != 1 {
		t.Fatalf("journal : %d créations, %d révocations", created, revoked)
	}
}

func mustPAT(t *testing.T) string {
	t.Helper()
	tok, err := token.New(token.Personal)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Plaintext
}

func TestPersonalTokenValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, s := setup(t)
	u, _, err := s.Create(ctx, audit.System, "v@example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		days int
		key  string
	}{
		{"", 30, account.KeyTokenNameInvalid}, {strings.Repeat("x", 101), 30, account.KeyTokenNameInvalid},
		{"a\x01", 30, account.KeyTokenNameInvalid}, {"ok", 0, account.KeyTokenExpiryInvalid}, {"ok", 3650, account.KeyTokenExpiryInvalid},
	} {
		if _, _, err := s.CreatePersonalToken(ctx, audit.System, u.ID, c.name, c.days); !isKey(err, c.key) {
			t.Errorf("%q %d : %v", c.name, c.days, err)
		}
	}
	for i := range account.MaxPersonalTokens {
		if _, _, err := s.CreatePersonalToken(ctx, audit.System, u.ID, "j", 7); err != nil {
			t.Fatalf("jeton %d : %v", i, err)
		}
	}
	if _, _, err := s.CreatePersonalToken(ctx, audit.System, u.ID, "j", 7); !isKey(err, account.KeyTokenLimit) {
		t.Fatalf("au-delà de la borne : %v", err)
	}
	if _, _, err := s.CreatePersonalToken(ctx, audit.System, 999999, "j", 7); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("compte inconnu : %v", err)
	}
}
