package web

import (
	"slices"
	"strconv"
	"testing"

	"leblanc.io/open-go-sbom/internal/account"
	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/org"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/locales"
)

// TestDynamicKeysExist couvre les clés que les gabarits composent à l'exécution : actions
// du journal, rôles, messages flash, erreurs de saisie.
func TestDynamicKeysExist(t *testing.T) {
	keys, err := locales.Keys()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, a := range audit.Actions() {
		want = append(want, a.Key())
	}
	for _, r := range tenant.Roles() {
		want = append(want, "role."+string(r))
	}
	for _, k := range flashes {
		want = append(want, k)
	}
	for _, l := range account.Languages {
		want = append(want, "language."+l)
	}
	want = append(want,
		account.KeyEmailInvalid, account.KeyPasswordTooShort, account.KeyPasswordTooLong, account.KeyPasswordIsEmail,
		account.KeyPasswordUnchanged, account.KeyPasswordMismatch, account.KeyPasswordWrong, account.KeyLanguageInvalid,
		account.KeyThemeInvalid, account.KeyDefaultOrgInvalid, account.KeyEmailTaken, account.KeyLastAdmin,
		account.KeyCannotTargetSelf, account.KeyRescueTicketTooShort,
		org.KeySlugInvalid, org.KeySlugTaken, org.KeyNameInvalid, org.KeyLanguage, org.KeyRoleInvalid,
		org.KeyMemberExists, org.KeyUnknownAccount, org.KeyLastOrgAdmin,
		"login.error.invalid_credentials", "login.error.attempts_exhausted", "verify.error.invalid_code",
		"totp_setup.error.invalid_code", "error.csrf.title", "error.csrf.text")
	want = append(want, project.ValidationKeys()...)
	want = append(want, agent.ValidationKeys()...)
	for _, k := range agent.ErrorKeys() {
		want = append(want, k+".title", k+".text")
	}
	for _, k := range project.Kinds() {
		want = append(want, "project_type."+string(k))
	}
	for _, k := range agent.Kinds() {
		want = append(want, "agent_type."+string(k))
	}
	for _, s := range []agent.State{agent.StateActive, agent.StatePending, agent.StateDisabled} {
		want = append(want, "agent_state."+string(s))
	}
	for _, d := range agent.TokenLifetimes {
		want = append(want, "agents.expiry_"+strconv.Itoa(d))
	}
	for _, h := range agent.EnrollmentLifetimes {
		want = append(want, "enrollment.expiry_"+strconv.Itoa(h))
	}
	for _, k := range want {
		if !slices.Contains(keys, k) {
			t.Errorf("clé %s absente des traductions", k)
		}
	}
}

func TestGroupBy4(t *testing.T) {
	if got := groupBy4("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Fatal(got)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/o/a": "/o/a", "//evil": "", "/login?x": "", "https://x": ""} {
		if got := safeNext(in); got != want {
			t.Errorf("%q : %q", in, got)
		}
	}
}
