//go:build integration

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
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

// reconfiguredPassword est le nouveau mot de passe choisi à la reconfiguration du TOTP.
const reconfiguredPassword = "une toute nouvelle phrase de passe"

// reconfigureForm : formulaire de reconfiguration du TOTP avec code, nouveau mot de passe
// et confirmation.
func reconfigureForm(code string) url.Values {
	return url.Values{"reconfigure_code": {code}, "password": {reconfiguredPassword}, "confirm": {reconfiguredPassword}}
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
	if p = other.post(pathSecurity+"/reconfigure", reconfigureForm("pas-un-code")); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("reconfiguration avec un code faux : %d", p.status)
	}
	if p = other.post(pathSecurity+"/reconfigure", reconfigureForm(codes[1])); p.status != http.StatusSeeOther ||
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
	if p = fresh.post("/login", url.Values{"email": {u.Email}, "password": {reconfiguredPassword}}); p.location != pathTOTPSetup {
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
	u.Password = reconfiguredPassword
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
	if p := b.post(pathSecurity+"/reconfigure", reconfigureForm("000000")); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("code TOTP faux : %d", p.status)
	}
	if p := b.post(pathSecurity+"/reconfigure", reconfigureForm(a.code(u.ID, u.Secret))); p.status != http.StatusSeeOther {
		t.Fatalf("reconfiguration par code TOTP : %d\n%s", p.status, p.body)
	}
	if n := countAction(a.instanceActions(), audit.AccountTOTPReconfigured); n != 1 {
		t.Fatalf("événements de reconfiguration : %d", n)
	}
}

// TestReconfigureClosesPasswordOnlyWindow : SEC2-06. La reconfiguration du TOTP impose un
// nouveau mot de passe : entre la reconfiguration et la reconnexion du titulaire, l'ancien
// mot de passe (peut-être dérobé, arrêté jusque-là par le TOTP) n'ouvre plus l'enrôlement
// d'un second facteur. Un mot de passe refusé ne consomme pas le code de secours.
func TestReconfigureClosesPasswordOnlyWindow(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("carol@example.org", false)
	b := a.signIn(u)
	codes := recoveryCodesIn(b.post(pathSecurity+"/recovery-codes", url.Values{"code": {a.code(u.ID, u.Secret)}}).body)
	if len(codes) != 10 {
		t.Fatalf("codes générés : %d", len(codes))
	}

	for name, form := range map[string]url.Values{
		"confirmation différente": {"reconfigure_code": {codes[0]}, "password": {reconfiguredPassword}, "confirm": {"autre chose encore"}},
		"trop court":              {"reconfigure_code": {codes[0]}, "password": {"court"}, "confirm": {"court"}},
		"inchangé":                {"reconfigure_code": {codes[0]}, "password": {u.Password}, "confirm": {u.Password}},
	} {
		if p := b.post(pathSecurity+"/reconfigure", form); p.status != http.StatusUnprocessableEntity {
			t.Fatalf("%s : %d", name, p.status)
		}
	}
	if p := b.get(pathSecurity); !strings.Contains(p.body, "Restants : 10 sur 10") {
		t.Fatal("un mot de passe refusé a consommé le code de secours")
	}
	if p := b.post(pathSecurity+"/reconfigure", reconfigureForm(codes[0])); p.status != http.StatusSeeOther {
		t.Fatalf("reconfiguration : %d", p.status)
	}

	// L'attaquant qui connaît l'ancien mot de passe n'ouvre pas de session de configuration.
	attacker := a.browser()
	if p := attacker.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}}); p.location == pathTOTPSetup || p.status != http.StatusUnauthorized {
		t.Fatalf("ancien mot de passe après la reconfiguration : %d %q", p.status, p.location)
	}
	if p := attacker.get(pathTOTPSetup); p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, pathLogin) {
		t.Fatalf("page d'enrôlement sans session : %d %q", p.status, p.location)
	}
	holder := a.browser()
	if p := holder.post("/login", url.Values{"email": {u.Email}, "password": {reconfiguredPassword}}); p.location != pathTOTPSetup {
		t.Fatalf("nouveau mot de passe : %d %q, attendu l'enrôlement", p.status, p.location)
	}
}

// TestEnableOnActiveTOTPDeliversNothing : SEC2-01. Une session volée ne devine plus, par
// force brute sur /account/totp/enable, un code TOTP qui délivrerait un nouveau jeu de
// codes de secours : un TOTP actif ne se « réactive » pas, sans même examiner le code, et
// le jeu du titulaire reste valide.
func TestEnableOnActiveTOTPDeliversNothing(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("victim@example.org", false)
	b := a.signIn(u) // session dérobée
	if codes := recoveryCodesIn(b.post(pathSecurity+"/recovery-codes", url.Values{"code": {a.code(u.ID, u.Secret)}}).body); len(codes) != 10 {
		t.Fatalf("codes du titulaire : %d", len(codes))
	}
	for i := range 30 {
		if p := b.post(pathTOTPOn, url.Values{"code": {fmt.Sprintf("%06d", 100000+i)}}); p.status != http.StatusSeeOther || p.location != pathSecurity {
			t.Fatalf("essai %d sur un TOTP actif : %d %q", i, p.status, p.location)
		}
	}
	p := b.post(pathTOTPOn, url.Values{"code": {a.code(u.ID, u.Secret)}})
	if p.status != http.StatusSeeOther || p.location != pathSecurity || len(recoveryCodesIn(p.body)) != 0 {
		t.Fatalf("code juste sur un TOTP actif : %d %q, %d codes", p.status, p.location, len(recoveryCodesIn(p.body)))
	}
	if p = b.get(pathSecurity); !strings.Contains(p.body, "Restants : 10 sur 10") {
		t.Fatal("le jeu du titulaire a été remplacé")
	}
	if n := countAction(a.instanceActions(), audit.RecoveryCodesGenerated); n != 1 {
		t.Fatalf("jeux générés : %d, attendu 1", n)
	}
}

// TestEnrollmentCodesCountInLockout : SEC2-01. Pendant l'enrôlement, chaque code faux
// compte dans le verrouillage par compte (open-go-base v1.4.1) ; au seuil, le compte est
// verrouillé, journalisé, et la page d'enrôlement le dit.
func TestEnrollmentCodesCountInLockout(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	u := a.user("dave@example.org", false)
	ctx := context.Background()
	if err := a.tdb.App.InTx(ctx, func(tx *db.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM mfa_totp WHERE user_id = $1`, u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	b := a.browser()
	if p := b.post("/login", url.Values{"email": {u.Email}, "password": {u.Password}}); p.location != pathTOTPSetup {
		t.Fatalf("connexion sans TOTP : %d %q", p.status, p.location)
	}
	key := setupSecret(t, b.get(pathTOTPSetup).body)
	var last page
	for range 10 {
		last = b.post(pathTOTPOn, url.Values{"code": {"000000"}})
	}
	if last.location != pathTOTPSetup+"?error=2fa_locked" {
		t.Fatalf("10e code faux à l'enrôlement : %d %q", last.status, last.location)
	}
	if p := b.get(last.location); !strings.Contains(unescape(p.body), "le compte est verrouillé") {
		t.Fatal("message du verrouillage absent de la page d'enrôlement")
	}
	code, _ := totp.GenerateCode(key, time.Now())
	if p := b.post(pathTOTPOn, url.Values{"code": {code}}); p.location != pathTOTPSetup+"?error=2fa_locked" || len(recoveryCodesIn(p.body)) != 0 {
		t.Fatalf("code juste sur un compte verrouillé : %d %q", p.status, p.location)
	}
	if n := countAction(a.instanceActions(), audit.AccountLocked); n != 1 {
		t.Fatalf("verrouillages journalisés : %d", n)
	}
}
