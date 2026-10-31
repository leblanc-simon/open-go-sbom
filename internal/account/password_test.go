package account

import (
	"strings"
	"testing"
)

func TestPasswordPolicyTwelveCharactersMinimum(t *testing.T) {
	cases := map[string]struct {
		password, email, key string
	}{
		"trop court":                {"onze-caract", "", KeyPasswordTooShort},
		"douze caractères":          {"douze-caract", "", ""},
		"multi-octets comptés":      {"éééééééééééé", "", ""},
		"trop long":                 {strings.Repeat("a", MaxPasswordLength+1), "", KeyPasswordTooLong},
		"égal à l'e-mail":           {"Alice@Example.org", "alice@example.org", KeyPasswordIsEmail},
		"sans règle de composition": {"aaaaaaaaaaaa", "", ""},
	}
	for name, c := range cases {
		err := ValidatePassword(c.password, c.email)
		v, ok := IsValidation(err)
		switch {
		case c.key == "" && err != nil:
			t.Errorf("%s : refusé (%v)", name, err)
		case c.key != "" && (!ok || v.Key != c.key):
			t.Errorf("%s : %v, attendu %s", name, err, c.key)
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	if e, err := NormalizeEmail("  Alice@Example.ORG "); err != nil || e != "alice@example.org" {
		t.Fatalf("%q, %v", e, err)
	}
	for _, bad := range []string{"", "alice", "Alice <alice@example.org>", "a b@example.org", strings.Repeat("a", 250) + "@example.org"} {
		if _, err := NormalizeEmail(bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestGeneratePasswordIsLongAndUnambiguous(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		p := GeneratePassword()
		if len(p) != TempPasswordLength || ValidatePassword(p, "") != nil || strings.ContainsAny(p, "0O1lI") {
			t.Fatalf("mot de passe temporaire %q", p)
		}
		if seen[p] {
			t.Fatal("mot de passe temporaire répété")
		}
		seen[p] = true
	}
}

func TestValidationErrorMessage(t *testing.T) {
	err := &ValidationError{Field: "email", Key: KeyEmailInvalid}
	if !strings.Contains(err.Error(), "validation.email_invalid") {
		t.Fatal(err.Error())
	}
	if _, ok := IsValidation(ErrNotFound); ok {
		t.Fatal("ErrNotFound n'est pas une erreur de saisie")
	}
}
