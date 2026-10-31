//go:build integration

package account_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	authsql "leblanc.io/open-go-base/authx/sqlstore"
	mfasql "leblanc.io/open-go-base/mfax/sqlstore"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db/dbtest"
	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/org"
	"leblanc.io/open-go-sbom/internal/secret"
	"leblanc.io/open-go-sbom/internal/tenant"
)

const cost = 4

func setup(t *testing.T) (*dbtest.DB, *account.Service) {
	t.Helper()
	tdb := dbtest.New(t)
	return tdb, account.NewService(tdb.App, cost)
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func isKey(err error, k string) bool {
	v, ok := account.IsValidation(err)
	return ok && v.Key == k
}

func TestCreateListAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, s := setup(t)
	for _, e := range []string{"c@example.org", "a@example.org", "b@example.org"} {
		u, pw, err := s.Create(ctx, audit.System, e, e == "a@example.org")
		if err != nil || pw == "" || !u.MustChangePwd || u.TOTPEnabled || !u.Active {
			t.Fatalf("création de %s : %+v, %v", e, u, err)
		}
	}
	if _, _, err := s.Create(ctx, audit.System, "A@example.org", false); !isKey(err, account.KeyEmailTaken) {
		t.Fatalf("doublon : %v", err)
	}
	if _, _, err := s.Create(ctx, audit.System, "pas une adresse", false); !isKey(err, account.KeyEmailInvalid) {
		t.Fatalf("adresse invalide : %v", err)
	}
	p1, err := s.List(ctx, "", 2)
	if err != nil || len(p1.Items) != 2 || p1.Items[0].Email != "a@example.org" || p1.NextCursor == "" {
		t.Fatalf("page 1 : %+v, %v", p1, err)
	}
	p2, err := s.List(ctx, p1.NextCursor, 2)
	if err != nil || len(p2.Items) != 1 || p2.Items[0].Email != "c@example.org" || p2.NextCursor != "" {
		t.Fatalf("page 2 : %+v, %v", p2, err)
	}
	if _, err := s.List(ctx, "illisible", 2); err == nil {
		t.Fatal("curseur illisible accepté")
	}
	if _, err := s.List(ctx, "", 0); err == nil {
		t.Fatal("taille 0 acceptée")
	}
	a, err := s.GetByEmail(ctx, " A@Example.org")
	if err != nil || !a.Admin {
		t.Fatalf("GetByEmail : %+v, %v", a, err)
	}
	if _, err := s.GetByEmail(ctx, "absent@example.org"); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("absent : %v", err)
	}
	if _, err := s.GetByEmail(ctx, "invalide"); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("invalide : %v", err)
	}
	if _, err := s.Get(ctx, 9999); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("identifiant inconnu : %v", err)
	}
	if n, err := s.ActiveAdmins(ctx); err != nil || n != 1 {
		t.Fatalf("administrateurs : %d, %v", n, err)
	}
}

// TestLastInstanceAdminIsKept : le dernier administrateur d'instance actif ne peut être
// ni désactivé ni rétrogradé, et un administrateur ne se désactive pas lui-même.
func TestLastInstanceAdminIsKept(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, s := setup(t)
	a, _, _ := s.Create(ctx, audit.System, "a@example.org", true)
	b, _, _ := s.Create(ctx, audit.System, "b@example.org", false)
	actorB := audit.Actor{UserID: b.ID, Email: b.Email}
	if err := s.SetAdmin(ctx, actorB, a.ID, false); !isKey(err, account.KeyLastAdmin) {
		t.Fatalf("rétrogradation : %v", err)
	}
	if err := s.SetActive(ctx, actorB, a.ID, false); !isKey(err, account.KeyLastAdmin) {
		t.Fatalf("désactivation : %v", err)
	}
	if err := s.SetActive(ctx, audit.Actor{UserID: a.ID}, a.ID, false); !isKey(err, account.KeyCannotTargetSelf) {
		t.Fatalf("auto-désactivation : %v", err)
	}
	if err := s.SetAdmin(ctx, actorB, b.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetActive(ctx, actorB, a.ID, false); err != nil {
		t.Fatalf("désactivation avec un autre administrateur : %v", err)
	}
	if err := s.SetActive(ctx, actorB, 9999, true); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("compte inconnu : %v", err)
	}
}

func TestPasswordChangeAndReset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb, s := setup(t)
	u, temp, _ := s.Create(ctx, audit.System, "u@example.org", false)
	sessions := authsql.NewSessionStore(tdb.App.DB(), appconf.DialectPostgres)
	for _, tok := range []string{"keep", "other"} {
		if err := sessions.Create(&authx.Session{Token: tok, UserID: u.ID, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	const next = "nouvelle phrase de passe"
	actor := audit.Actor{UserID: u.ID, Email: u.Email}
	for _, c := range []struct {
		current, next, confirm, key string
	}{
		{temp, next, "autre", account.KeyPasswordMismatch},
		{"faux", next, next, account.KeyPasswordWrong},
		{temp, "court", "court", account.KeyPasswordTooShort},
		{temp, temp, temp, account.KeyPasswordUnchanged},
	} {
		if err := s.ChangePassword(ctx, actor, u.ID, c.current, c.next, c.confirm, "keep", false); !isKey(err, c.key) {
			t.Errorf("%s : %v", c.key, err)
		}
	}
	if err := s.ChangePassword(ctx, actor, 9999, temp, next, next, "", false); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("compte inconnu : %v", err)
	}
	if err := s.ChangePassword(ctx, actor, u.ID, temp, next, next, "keep", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, u.ID); got.MustChangePwd {
		t.Error("must_change_pwd non levé")
	}
	if _, err := sessions.Get("other"); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Error("autre session conservée")
	}
	if _, err := sessions.Get("keep"); err != nil {
		t.Error("session courante fermée")
	}
	pw, err := s.ResetPassword(ctx, audit.System, u.ID)
	if err != nil || pw == next {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, u.ID); !got.MustChangePwd {
		t.Error("must_change_pwd non posé par la réinitialisation")
	}
	if _, err := sessions.Get("keep"); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Error("sessions conservées après réinitialisation")
	}
	if _, err := s.ResetPassword(ctx, audit.System, 9999); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("réinitialisation d'un compte inconnu : %v", err)
	}
}

// TestBootstrapCreatesFirstAdminOnce : le premier administrateur n'est créé que sur une
// base sans compte.
func TestBootstrapCreatesFirstAdminOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, s := setup(t)
	if _, err := s.Bootstrap(ctx, "admin@example.org", "court"); !isKey(err, account.KeyPasswordTooShort) {
		t.Fatalf("mot de passe court : %v", err)
	}
	if _, err := s.Bootstrap(ctx, "invalide", "mot de passe temporaire"); err == nil {
		t.Fatal("adresse invalide acceptée")
	}
	created, err := s.Bootstrap(ctx, "admin@example.org", "mot de passe temporaire")
	if err != nil || !created {
		t.Fatalf("premier démarrage : %v, %v", created, err)
	}
	again, err := s.Bootstrap(ctx, "autre@example.org", "mot de passe temporaire")
	if err != nil || again {
		t.Fatalf("second démarrage : %v, %v", again, err)
	}
	u, err := s.GetByEmail(ctx, "admin@example.org")
	if err != nil || !u.Admin || !u.MustChangePwd {
		t.Fatalf("administrateur : %+v, %v", u, err)
	}
	if _, err := s.GetByEmail(ctx, "autre@example.org"); !errors.Is(err, account.ErrNotFound) {
		t.Fatal("second bootstrap appliqué")
	}
}

func TestStartup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb, s := setup(t)
	box, _ := secret.New(map[string][]byte{"k1": key(1)}, "k1")
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	if err := s.Startup(ctx, account.StartupOptions{}, tdb.App, box, logger); err != nil || !strings.Contains(logs.String(), "aucun administrateur") {
		t.Fatalf("sans compte : %v\n%s", err, logs)
	}
	o := account.StartupOptions{AdminEmail: "admin@example.org", AdminPassword: "mot de passe temporaire",
		RescueEmail: "admin@example.org", RescueTicket: "INC-0001-2026", RescuePassword: "mot de passe de secours"}
	for range 2 {
		if err := s.Startup(ctx, o, tdb.App, box, logger); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(logs.String(), "premier administrateur créé") || !strings.Contains(logs.String(), "déjà appliquée") {
		t.Fatalf("journaux :\n%s", logs)
	}
	if err := s.Startup(ctx, account.StartupOptions{RescueEmail: "absent@example.org", RescueTicket: "INC-0002-2026",
		RescuePassword: "mot de passe de secours"}, tdb.App, box, logger); !errors.Is(err, account.ErrRescueNotAdmin) {
		t.Fatalf("secours d'un compte absent : %v", err)
	}
	if err := s.Startup(ctx, account.StartupOptions{AdminEmail: "x", AdminPassword: "y"}, tdb.App, box, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("bootstrap invalide accepté")
	}
}

// TestTOTPSecretsAreSealedAndRotated : le secret TOTP n'est jamais en clair en base, est
// lié à son compte, et passe à la clé active au rechiffrement.
func TestTOTPSecretsAreSealedAndRotated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb, s := setup(t)
	u, _, _ := s.Create(ctx, audit.System, "u@example.org", false)
	v, _, _ := s.Create(ctx, audit.System, "v@example.org", false)
	old, _ := secret.New(map[string][]byte{"old": key(1)}, "old")
	inner := mfasql.NewTOTPStore(tdb.App.DB(), appconf.DialectPostgres)
	store := account.NewSealedTOTPStore(inner, old, tdb.App)
	if err := store.Set(u.ID, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatal(err)
	}
	raw, err := inner.Get(u.ID)
	if err != nil || strings.Contains(raw.Secret, "JBSWY3DPEHPK3PXP") || !strings.HasPrefix(raw.Secret, "s1:old:") {
		t.Fatalf("stocké : %q, %v", raw.Secret, err)
	}
	got, err := store.Get(u.ID)
	if err != nil || got.Secret != "JBSWY3DPEHPK3PXP" || !got.Enabled {
		t.Fatalf("relu : %+v, %v", got, err)
	}
	// Un chiffré recopié sur un autre compte ne s'ouvre pas.
	if err := inner.Set(v.ID, raw.Secret, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(v.ID); !errors.Is(err, account.ErrUnsealedTOTP) {
		t.Fatalf("chiffré déplacé : %v", err)
	}
	if err := inner.Set(v.ID, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(v.ID); !errors.Is(err, account.ErrUnsealedTOTP) {
		t.Fatalf("secret en clair : %v", err)
	}
	if err := inner.Delete(v.ID); err != nil {
		t.Fatal(err)
	}
	both, _ := secret.New(map[string][]byte{"old": key(1), "new_2": key(2)}, "new_2")
	if n, err := account.RotateTOTPSecrets(ctx, tdb.App, both); err != nil || n != 1 {
		t.Fatalf("rechiffrement : %d, %v", n, err)
	}
	if n, err := account.RotateTOTPSecrets(ctx, tdb.App, both); err != nil || n != 0 {
		t.Fatalf("second rechiffrement : %d, %v", n, err)
	}
	only, _ := secret.New(map[string][]byte{"new_2": key(2)}, "new_2")
	if got, err := account.NewSealedTOTPStore(inner, only, tdb.App).Get(u.ID); err != nil || got.Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("après retrait de l'ancienne clé : %+v, %v", got, err)
	}
	pw, err := s.ResetTOTP(ctx, audit.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, u.ID); got.TOTPEnabled || !got.MustChangePwd || pw == "" {
		t.Fatalf("après réinitialisation du TOTP : %+v (mot de passe temporaire %v)", got, pw != "")
	}
}

func TestSessionRecorderAndPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb, s := setup(t)
	u, _, _ := s.Create(ctx, audit.System, "u@example.org", false)
	rec := account.NewSessionRecorder(authsql.NewSessionStore(tdb.App.DB(), appconf.DialectPostgres), tdb.App)
	if err := rec.Create(&authx.Session{Token: "setup", UserID: u.ID, Purpose: authx.PurposeSetup, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.SessionMethod(ctx, "setup"); err != nil || ok {
		t.Fatalf("session de configuration avec méthode : %v, %v", ok, err)
	}
	if err := rec.Create(&authx.Session{Token: "auth", UserID: u.ID, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if m, ok, err := s.SessionMethod(ctx, "auth"); err != nil || !ok || m != account.MethodLocalTOTP {
		t.Fatalf("méthode : %q, %v, %v", m, ok, err)
	}
	// Une session d'un compte inconnu ne peut pas recevoir de méthode : elle est retirée.
	if err := rec.Create(&authx.Session{Token: "x", UserID: 9999, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("session sans compte acceptée")
	}
	n, err := s.PurgeExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge : %d, %v", n, err)
	}
	if _, ok, _ := s.SessionMethod(ctx, "auth"); ok {
		t.Fatal("méthode d'une session purgée conservée")
	}
	if err := s.PurgeHandler().Handle(ctx, jobsExecution()); err != nil {
		t.Fatal(err)
	}
	if sc := account.PurgeSchedule(); sc.Name != account.PurgeKind || sc.Job.Kind != account.PurgeKind {
		t.Fatalf("échéance %+v", sc)
	}
}

func TestSettingsAndViewer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb, s := setup(t)
	orgs := org.NewService(tdb.App)
	u, _, _ := s.Create(ctx, audit.System, "u@example.org", false)
	other, _, _ := s.Create(ctx, audit.System, "o@example.org", false)
	mine, err := orgs.Create(ctx, audit.System, "mine", "Mine", "fr", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	theirs, _ := orgs.Create(ctx, audit.System, "theirs", "Theirs", "en", other.ID)
	actor := audit.Actor{UserID: u.ID}
	if got, err := s.Settings(ctx, u.ID); err != nil || got != (account.Settings{}) {
		t.Fatalf("préférences vides : %+v, %v", got, err)
	}
	for _, c := range []struct {
		set account.Settings
		key string
	}{
		{account.Settings{Language: "de"}, account.KeyLanguageInvalid},
		{account.Settings{Theme: "pink"}, account.KeyThemeInvalid},
		{account.Settings{DefaultOrg: theirs.ID}, account.KeyDefaultOrgInvalid},
	} {
		if err := s.SaveSettings(ctx, actor, u.ID, c.set); !isKey(err, c.key) {
			t.Errorf("%s : %v", c.key, err)
		}
	}
	want := account.Settings{Language: "en", Theme: "dark", DefaultOrg: mine.ID}
	if err := s.SaveSettings(ctx, actor, u.ID, want); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Settings(ctx, u.ID); err != nil || got != want {
		t.Fatalf("préférences : %+v, %v", got, err)
	}
	v, err := s.Viewer(ctx, u.ID, "aucune")
	if err != nil || v.HasMethod || v.TOTPEnabled || v.Settings != want || len(v.Orgs) != 1 || v.Orgs[0].Role != tenant.RoleAdmin {
		t.Fatalf("visiteur : %+v, %v", v, err)
	}
	if err := s.SaveSettings(ctx, actor, u.ID, account.Settings{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Settings(ctx, u.ID); got != (account.Settings{}) {
		t.Fatalf("préférences effacées : %+v", got)
	}
}

func jobsExecution() jobs.Execution { return jobs.Execution{} }
