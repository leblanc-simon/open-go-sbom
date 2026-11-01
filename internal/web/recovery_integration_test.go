//go:build integration

package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/web/webtest"
)

var recoveryCodeItem = regexp.MustCompile(`<li><code>([0-9a-z]{4}(?:-[0-9a-z]{4}){3})</code></li>`)

// recoveryCodesIn relève les codes de secours affichés par une page.
func recoveryCodesIn(body string) []string {
	var out []string
	for _, m := range recoveryCodeItem.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// passwordStep joue le mot de passe de u dans un nouveau navigateur et renvoie celui-ci,
// arrivé à la saisie du second facteur.
func (a *app) passwordStep(u user) *browser {
	a.t.Helper()
	b := a.browser()
	if p := b.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}}); p.location != pathVerify {
		a.t.Fatalf("mot de passe de %s : %d %q", u.Email, p.status, p.location)
	}
	return b
}

// TestRecoveryCodes : critère de T18 « un utilisateur peut se connecter avec un code de
// secours, à usage unique ». Un compte enrôlé avant les codes en génère un jeu (code TOTP
// exigé), se connecte avec l'un d'eux une seule fois, puis reconfigure son application par
// un autre code : le TOTP reste obligatoire (nouvel enrôlement) et l'ancien jeu est caduc.
func TestRecoveryCodes(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("alice@example.org", false)
	b := a.signIn(u)

	// Compte sans codes : la page l'invite à en générer.
	p := b.get(pathSecurity)
	if p.status != http.StatusOK || !strings.Contains(p.body, "Aucun code de secours") || !strings.Contains(p.body, "Restants : 0 sur 10") {
		t.Fatalf("page du second facteur : %d", p.status)
	}
	webtest.AssertAccessible(t, []byte(p.body))
	webtest.AssertNoInlineCode(t, []byte(p.body))

	// Régénération : un code faux est refusé sans rien générer, le bon montre le jeu une fois.
	if p = b.post(pathSecurity+"/recovery-codes", url.Values{"code": {"000000"}}); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(unescape(p.body), "incorrect, expiré ou déjà utilisé") || len(recoveryCodesIn(p.body)) != 0 {
		t.Fatalf("régénération avec un code faux : %d", p.status)
	}
	p = b.post(pathSecurity+"/recovery-codes", url.Values{"code": {a.code(u.ID, u.Secret)}})
	codes := recoveryCodesIn(p.body)
	if p.status != http.StatusOK || len(codes) != 10 || p.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("régénération : %d, %d codes, Cache-Control %q", p.status, len(codes), p.header.Get("Cache-Control"))
	}
	webtest.AssertAccessible(t, []byte(p.body))
	if p = b.get(pathSecurity); len(recoveryCodesIn(p.body)) != 0 || !strings.Contains(p.body, "Restants : 10 sur 10") {
		t.Fatal("les codes sont réaffichés, ou le compte est faux")
	}

	// Connexion : la page du second facteur propose le code de secours.
	other := a.passwordStep(u)
	verify := other.get(pathVerify)
	if !strings.Contains(verify.body, `name="recovery_code"`) {
		t.Fatal("champ du code de secours absent")
	}
	webtest.AssertAccessible(t, []byte(verify.body))
	if p = other.post(pathVerify, url.Values{"recovery_code": {"0000-0000-0000-0000"}}); p.status != http.StatusUnauthorized ||
		!strings.Contains(unescape(p.body), "code de secours est incorrect") || !strings.Contains(p.body, "<details class=\"auth__alt\" open>") {
		t.Fatalf("code de secours faux : %d", p.status)
	}
	webtest.AssertAccessible(t, []byte(p.body))
	// Saisie tolérante : majuscules, espaces au lieu des tirets.
	typed := strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))
	if p = other.post(pathVerify, url.Values{"recovery_code": {typed}}); p.status != http.StatusSeeOther ||
		p.location != pathSecurity+"?done="+doneRecoverySignIn {
		t.Fatalf("connexion par code de secours : %d %q", p.status, p.location)
	}
	if p = other.get(p.location); p.status != http.StatusOK || !strings.Contains(p.body, "connecté avec un code de secours") ||
		!strings.Contains(p.body, "Restants : 9 sur 10") {
		t.Fatalf("arrivée après le code de secours : %d", p.status)
	}

	// Usage unique : le même code ne rouvre pas de session.
	third := a.passwordStep(u)
	if p = third.post(pathVerify, url.Values{"recovery_code": {codes[0]}}); p.status != http.StatusUnauthorized {
		t.Fatalf("code de secours rejoué : %d", p.status)
	}

	// Application perdue : un autre code de secours la retire, ferme les sessions et impose
	// un nouvel enrôlement.
	if p = other.post(pathSecurity+"/reconfigure", url.Values{"reconfigure_code": {"pas-un-code"}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("reconfiguration avec un code faux : %d", p.status)
	}
	if p = other.post(pathSecurity+"/reconfigure", url.Values{"reconfigure_code": {codes[1]}}); p.status != http.StatusSeeOther ||
		p.location != pathLogin+"?done="+doneTOTPReconfigured {
		t.Fatalf("reconfiguration : %d %q", p.status, p.location)
	}
	for _, br := range []*browser{b, other} {
		if p = br.get("/account"); p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, pathLogin) {
			t.Fatalf("session encore ouverte après la reconfiguration : %d %q", p.status, p.location)
		}
	}
	if p = other.get(pathLogin + "?done=" + doneTOTPReconfigured); !strings.Contains(unescape(p.body), "second facteur a été retiré") {
		t.Fatal("message de la reconfiguration absent")
	}
	webtest.AssertAccessible(t, []byte(p.body))
	fresh := a.browser()
	if p = fresh.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}}); p.location != pathTOTPSetup {
		t.Fatalf("connexion après la reconfiguration : %d %q, attendu l'enrôlement", p.status, p.location)
	}
	key := setupSecret(t, fresh.get(pathTOTPSetup).body)
	code, _ := totp.GenerateCode(key, time.Now())
	p = fresh.post(pathTOTPOn, url.Values{"code": {code}})
	newCodes := recoveryCodesIn(p.body)
	if p.status != http.StatusOK || len(newCodes) != 10 || p.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("nouvel enrôlement : %d, %d codes", p.status, len(newCodes))
	}
	webtest.AssertAccessible(t, []byte(p.body))
	webtest.AssertNoInlineCode(t, []byte(p.body))
	if p = fresh.get(pathHome); p.status == http.StatusSeeOther && strings.HasPrefix(p.location, pathLogin) {
		t.Fatal("session non ouverte après le nouvel enrôlement")
	}
	// L'ancien jeu est caduc.
	last := a.passwordStep(u)
	if p = last.post(pathVerify, url.Values{"recovery_code": {codes[2]}}); p.status != http.StatusUnauthorized {
		t.Fatalf("code de l'ancien jeu : %d", p.status)
	}

	actions := a.instanceActions()
	for want, n := range map[audit.Action]int{
		audit.RecoveryCodesGenerated: 2, audit.RecoveryCodeUsed: 2, audit.RecoveryCodeFailed: 3,
		audit.AccountTOTPReconfigured: 1,
	} {
		if got := countAction(actions, want); got != n {
			t.Errorf("%s : %d événements, attendu %d", want, got, n)
		}
	}
	for _, c := range append(codes, newCodes...) {
		if strings.Contains(a.logs.String(), c) {
			t.Fatal("un code de secours apparaît dans les journaux")
		}
	}
}

// TestReconfigureWithTOTPCode : la reconfiguration accepte aussi un code TOTP ; les codes
// faux comptent dans le verrouillage par compte.
func TestReconfigureWithTOTPCode(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("bob@example.org", false)
	b := a.signIn(u)
	if p := b.post(pathSecurity+"/reconfigure", url.Values{"reconfigure_code": {"000000"}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("code TOTP faux : %d", p.status)
	}
	if p := b.post(pathSecurity+"/reconfigure", url.Values{"reconfigure_code": {a.code(u.ID, u.Secret)}}); p.status != http.StatusSeeOther {
		t.Fatalf("reconfiguration par code TOTP : %d\n%s", p.status, p.body)
	}
	if n := countAction(a.instanceActions(), audit.AccountTOTPReconfigured); n != 1 {
		t.Fatalf("événements de reconfiguration : %d", n)
	}
}
