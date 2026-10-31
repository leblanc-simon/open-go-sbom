//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/open-go-base/csrfx"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
)

// Tests de non-régression de la revue de sécurité du lot 1 (T11) : les trois premiers
// reprennent les tests de démonstration de la revue, attentes inversées.

// TestSecReviewPATRevokedOnCredentialReset (SEC-02) : un jeton personnel ne survit ni à
// la réinitialisation du mot de passe ni à celle du TOTP.
func TestSecReviewPATRevokedOnCredentialReset(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", true)
	u := a.user("bob@example.org", false)
	actor := audit.Actor{UserID: admin.ID, Email: admin.Email}
	for name, reset := range map[string]func(context.Context, audit.Actor, int64) (string, error){
		"mot de passe": a.accounts.ResetPassword,
		"TOTP":         a.accounts.ResetTOTP,
	} {
		// Le compte redevient utilisable avant chaque jeton (mot de passe définitif, TOTP).
		a.restore(u)
		_, issued, err := a.accounts.CreatePersonalToken(ctx, audit.Actor{UserID: u.ID, Email: u.Email}, u.ID, "attaquant", 365)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reset(ctx, actor, u.ID); err != nil {
			t.Fatal(err)
		}
		_, err = a.accounts.AuthenticateToken(ctx, issued.Plaintext)
		if te, ok := err.(*account.TokenError); !ok || te.Key != account.KeyTokenRevoked {
			t.Fatalf("après réinitialisation du %s : %v, attendu %s", name, err, account.KeyTokenRevoked)
		}
	}
}

// TestSecReviewTOTPResetRequiresNewPassword (SEC-03) : après réinitialisation du TOTP,
// l'ancien mot de passe ne permet plus d'enrôler un second facteur ; seul le mot de passe
// temporaire remis par l'administrateur le permet, et il doit ensuite être changé.
func TestSecReviewTOTPResetRequiresNewPassword(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	ctx := context.Background()
	admin := a.user("admin@example.org", true)
	u := a.user("bob@example.org", false)
	temp, err := a.accounts.ResetTOTP(ctx, audit.Actor{UserID: admin.ID, Email: admin.Email}, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	attacker := a.browser()
	if p := attacker.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}}); p.status != http.StatusUnauthorized ||
		!strings.Contains(p.body, "Adresse e-mail ou mot de passe incorrect") {
		t.Fatalf("ancien mot de passe après réinitialisation du TOTP : %d %q", p.status, p.location)
	}
	owner := a.browser()
	if p := owner.post("/login", url.Values{"email": {u.Email}, "password": {temp}}); p.location != pathTOTPSetup {
		t.Fatalf("mot de passe temporaire : %d %q", p.status, p.location)
	}
	key := setupSecret(t, owner.get(pathTOTPSetup).body)
	code, _ := totp.GenerateCode(key, time.Now())
	if p := owner.post(pathTOTPOn, url.Values{"code": {code}}); p.status != http.StatusSeeOther || p.location != "/" {
		t.Fatalf("enrôlement : %d %q", p.status, p.location)
	}
	if p := owner.get("/account"); p.status != http.StatusSeeOther || p.location != pathPassword {
		t.Fatalf("changement du mot de passe temporaire non imposé : %d %q", p.status, p.location)
	}
}

// TestSecReviewTOTPLockoutAcrossChallenges (SEC-01) : rejouer le mot de passe pour ouvrir
// de nouveaux défis ne remet pas le compteur de codes faux à zéro ; au seuil (10), le
// compte est verrouillé : le mot de passe n'ouvre plus de défi, et le verrouillage est
// journalisé. La réinitialisation du TOTP par un administrateur le lève.
func TestSecReviewTOTPLockoutAcrossChallenges(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("bob@example.org", false)
	b := a.browser()
	failures := 0
	for failures < 10 {
		if p := b.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}}); !strings.HasPrefix(p.location, pathVerify) {
			t.Fatalf("défi %d : %d %q", failures, p.status, p.location)
		}
		for range 3 { // mfa.max_attempts du banc : 3 codes par défi
			p := b.post(pathVerify, url.Values{"code": {"000000"}})
			failures++
			if failures < 10 {
				if p.status != http.StatusUnauthorized {
					t.Fatalf("code faux %d : %d %q", failures, p.status, p.location)
				}
				continue
			}
			if p.status != http.StatusSeeOther || p.location != "/login?err=2fa_locked" {
				t.Fatalf("code faux %d : %d %q, attendu le verrouillage", failures, p.status, p.location)
			}
			break
		}
	}
	// Mot de passe juste : plus de défi, message générique de verrouillage.
	p := b.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}})
	if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/login?err=2fa_locked") {
		t.Fatalf("connexion d'un compte verrouillé : %d %q", p.status, p.location)
	}
	if page := b.get(p.location); !strings.Contains(unescape(page.body), "il est verrouillé pour un temps") {
		t.Fatalf("message de verrouillage absent :\n%s", page.body)
	}
	// Même le bon code, présenté sans défi, n'ouvre rien.
	if p := b.post(pathVerify, url.Values{"code": {a.code(u.ID, u.Secret)}}); p.location != "/login" {
		t.Fatalf("code juste d'un compte verrouillé : %d %q", p.status, p.location)
	}
	if !hasAction(a.instanceActions(), audit.AccountLocked) {
		t.Fatal("verrouillage absent du journal")
	}
	// Un administrateur lève le verrouillage en réinitialisant le TOTP.
	admin := a.user("admin@example.org", true)
	temp, err := a.accounts.ResetTOTP(context.Background(), audit.Actor{UserID: admin.ID, Email: admin.Email}, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p := a.browser().post("/login", url.Values{"email": {u.Email}, "password": {temp}}); p.location != pathTOTPSetup {
		t.Fatalf("après levée du verrouillage : %d %q", p.status, p.location)
	}
}

// TestSecReviewPATCreationStepUp (SEC-02) : un jeton personnel ne se crée qu'avec un code
// TOTP ; les codes faux comptent dans le verrouillage du compte.
func TestSecReviewPATCreationStepUp(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("bob@example.org", false)
	b := a.signIn(u)
	for i := range 9 {
		p := b.post(pathTokens, url.Values{"name": {"vol"}, "expires_in": {"365"}, "code": {"000000"}})
		if p.status != http.StatusUnprocessableEntity || patPattern.MatchString(p.body) {
			t.Fatalf("code faux %d : %d", i+1, p.status)
		}
	}
	p := b.post(pathTokens, url.Values{"name": {"vol"}, "expires_in": {"365"}, "code": {"000000"}})
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(unescape(p.body), "le compte est verrouillé") {
		t.Fatalf("dixième code faux : %d", p.status)
	}
	if p := b.post(pathTokens, url.Values{"name": {"vol"}, "expires_in": {"365"}, "code": {a.code(u.ID, u.Secret)}}); patPattern.MatchString(p.body) {
		t.Fatal("jeton créé par un compte verrouillé")
	}
	if tokens, err := a.accounts.PersonalTokens(context.Background(), u.ID); err != nil || len(tokens) != 0 {
		t.Fatalf("jetons : %d, %v", len(tokens), err)
	}
}

// TestSecReviewCSRFBoundToSession (SEC-08) : poser soi-même le cookie CSRF et le champ à la
// même valeur (cookie tossing depuis un sous-domaine) ne passe plus : le jeton attendu est
// lié à la session de la victime.
func TestSecReviewCSRFBoundToSession(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	admin := a.user("admin@example.org", true)
	b := a.signIn(admin)
	form := url.Values{"email": {"intrus@example.org"}, "csrf_token": {"pose-par-l-attaquant"}}
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/admin/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "lotor_session", Value: b.cookie("lotor_session")})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "pose-par-l-attaquant"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("double soumission forgée : %d, attendu 403", resp.StatusCode)
	}
	if _, err := a.accounts.GetByEmail(context.Background(), "intrus@example.org"); err == nil {
		t.Fatal("compte créé par une requête forgée")
	}
	// Le jeton d'une autre session ne vaut pas non plus.
	other := a.signIn(a.user("autre@example.org", true))
	form = url.Values{"email": {"intrus@example.org"}, "csrf_token": {other.csrf()}}
	req, _ = http.NewRequest(http.MethodPost, a.srv.URL+"/admin/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "lotor_session", Value: b.cookie("lotor_session")})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: other.cookie("csrf_token")})
	if resp, err = http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("jeton d'une autre session : %d, attendu 403", resp.StatusCode)
	}
	// Le formulaire rendu à la victime, lui, passe.
	if p := b.post("/admin/users", url.Values{"email": {"invite@example.org"}}); p.status != http.StatusOK {
		t.Fatalf("formulaire légitime : %d", p.status)
	}
}

// TestSecReviewSessionMaxAge (SEC-08) : une session glissante meurt quand même à sa durée
// absolue, comptée depuis la connexion.
func TestSecReviewSessionMaxAge(t *testing.T) {
	t.Parallel()
	a := newApp(t, func(o *RouterOptions) { o.Identity.SessionMaxAge = 7 * 24 * time.Hour })
	u := a.user("bob@example.org", false)
	b := a.signIn(u)
	if p := b.get("/account"); p.status != http.StatusOK {
		t.Fatalf("session neuve : %d", p.status)
	}
	if _, err := a.tdb.Owner(t).ExecContext(context.Background(),
		`UPDATE session_auth SET created_at = now() - interval '7 days 1 minute' WHERE user_id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if p := b.get("/account"); p.status != http.StatusSeeOther || p.location != "/login?next=%2Faccount" {
		t.Fatalf("session au-delà de sa durée absolue : %d %q", p.status, p.location)
	}
	var n int
	if err := a.tdb.App.DB().QueryRowContext(context.Background(), `SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("session non fermée : %d, %v", n, err)
	}
}

// TestSecReviewHostPrefixedCookies (SEC-08) : avec cookie_secure à on, les cookies de
// session, de défi TOTP et CSRF portent le préfixe __Host- (Secure, Path=/, sans Domain).
func TestSecReviewHostPrefixedCookies(t *testing.T) {
	t.Parallel()
	a := newApp(t, func(o *RouterOptions) {
		o.CSRFSecure = "on"
		o.Identity.Auth.CookieSecure = "on"
	})
	u := a.user("bob@example.org", false)
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	csrfCookie := hostCookieOf(t, rec, "__Host-csrf_token")

	var token string
	csrfx.New(csrfx.WithCookieName("__Host-csrf_token"), csrfx.WithSessionBinding(func(*http.Request) string { return "" })).
		Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { token = csrfx.Token(r) })).
		ServeHTTP(httptest.NewRecorder(), withCookies(httptest.NewRequest(http.MethodGet, "/", nil), csrfCookie))
	form := url.Values{"email": {u.Email}, "password": {u.Password}, "csrf_token": {token}}
	req := withCookies(httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode())), csrfCookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), pathVerify) {
		t.Fatalf("connexion : %d %q", rec.Code, rec.Header().Get("Location"))
	}
	hostCookieOf(t, rec, "__Host-mfa_challenge")
	for _, c := range rec.Result().Cookies() {
		if c.Name == "mfa_challenge" || c.Name == "csrf_token" || c.Name == "lotor_session" {
			t.Errorf("cookie sans préfixe : %s", c.Name)
		}
	}
}

// restore rend à u un mot de passe définitif et son TOTP, après une réinitialisation.
func (a *app) restore(u user) {
	a.t.Helper()
	sealed, err := seal(a.box, u.ID, u.Secret)
	if err != nil {
		a.t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := a.tdb.App.DB().ExecContext(ctx, `UPDATE users SET must_change_pwd = 0 WHERE id = $1`, u.ID); err != nil {
		a.t.Fatal(err)
	}
	if _, err := a.tdb.App.DB().ExecContext(ctx, `INSERT INTO mfa_totp (user_id, secret, enabled) VALUES ($1, $2, 1)
		ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, enabled = 1`, u.ID, sealed); err != nil {
		a.t.Fatal(err)
	}
}

func hostCookieOf(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			if !c.Secure || c.Path != "/" || c.Domain != "" {
				t.Errorf("%s : Secure=%v Path=%q Domain=%q", name, c.Secure, c.Path, c.Domain)
			}
			return c
		}
	}
	t.Fatalf("cookie %s absent", name)
	return nil
}

func withCookies(r *http.Request, cs ...*http.Cookie) *http.Request {
	for _, c := range cs {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}
