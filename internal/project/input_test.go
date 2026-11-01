package project

import (
	"slices"
	"strings"
	"testing"

	"leblanc.io/lotor/internal/account"
)

func keyOf(err error) string {
	if v, ok := account.IsValidation(err); ok {
		return v.Key
	}
	return ""
}

func TestParseLabels(t *testing.T) {
	l, err := ParseLabels(" env=prod, Exposé-Internet\nDC = paris ,, env=staging ")
	if err != nil {
		t.Fatal(err)
	}
	want := Labels{"env": "staging", "exposé-internet": "", "dc": "paris"}
	if len(l) != len(want) {
		t.Fatalf("%v", l)
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("%s = %q, attendu %q", k, l[k], v)
		}
	}
	if got := l.String(); got != "dc=paris, env=staging, exposé-internet" {
		t.Errorf("String : %q", got)
	}
	again, err := ParseLabels(l.String())
	if err != nil || again.String() != l.String() {
		t.Errorf("aller-retour : %v %v", again, err)
	}
	if err := l.Validate(); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"-x", "=v", "a=" + strings.Repeat("v", 101), "k\x01=v", strings.Repeat("k", 65)} {
		if _, err := ParseLabels(bad); keyOf(err) != KeyLabelInvalid {
			t.Errorf("%q : %v", bad, err)
		}
	}
	var many []string
	for i := range 21 {
		many = append(many, "k"+strings.Repeat("x", i))
	}
	if _, err := ParseLabels(strings.Join(many, ",")); keyOf(err) != KeyLabelsTooMany {
		t.Errorf("21 étiquettes : %v", err)
	}
	for _, bad := range []Labels{{"Env": "x"}, {"k": "a,b"}, {"k": "a=b"}} {
		if err := bad.Validate(); keyOf(err) != KeyLabelInvalid {
			t.Errorf("%v : %v", bad, err)
		}
	}
}

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"Portail Client":               "portail-client",
		"  Équipe   Ça va!  ":          "equipe-ca-va",
		"srv-db-02.example.org":        "srv-db-02-example-org",
		"___":                          "project",
		"日本":                           "project",
		strings.Repeat("a", 70) + "-b": strings.Repeat("a", 64),
	} {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, attendu %q", in, got, want)
		}
		if !slugPattern.MatchString(Slugify(in)) {
			t.Errorf("Slugify(%q) hors du motif", in)
		}
	}
}

func TestParseRefNames(t *testing.T) {
	refs, err := ParseRefNames("main, release/1.x\nmain  feature/é", "branches")
	if err != nil || !slices.Equal(refs, []string{"main", "release/1.x", "feature/é"}) {
		t.Fatalf("%v %v", refs, err)
	}
	for _, bad := range []string{"-x", "a..b", "a.lock", "/a", "a/", "a//b", "a:b", "a~1", "a^", "a?", "a*", "a[", `a\b`, "a@{1}", "a.", strings.Repeat("a", 256)} {
		if _, err := ParseRefNames(bad, "branches"); keyOf(err) != KeyRefInvalid {
			t.Errorf("%q : %v", bad, err)
		}
	}
	var many []string
	for i := range 51 {
		many = append(many, "b"+strings.Repeat("x", i))
	}
	if _, err := ParseRefNames(strings.Join(many, " "), "tags"); keyOf(err) != KeyRefsTooMany {
		t.Errorf("51 références : %v", err)
	}
}

func TestNormalizeHostRef(t *testing.T) {
	if h, err := NormalizeHostRef("  SRV-DB-02.Example.org "); err != nil || h != "srv-db-02.example.org" {
		t.Fatalf("%q %v", h, err)
	}
	for _, bad := range []string{"", "-x", "srv db", "srv/1", strings.Repeat("a", 101), "é"} {
		if _, err := NormalizeHostRef(bad); keyOf(err) != KeyHostRefInvalid {
			t.Errorf("%q : %v", bad, err)
		}
	}
}

func TestValidForgeURL(t *testing.T) {
	for _, ok := range []string{"", "https://git.example.org/a/b", "http://forge.local/x"} {
		if _, err := validForgeURL(ok); err != nil {
			t.Errorf("%q : %v", ok, err)
		}
	}
	for _, bad := range []string{"git@host:a/b", "ftp://x/y", "https://", "https://user:pw@git.example.org/a", "javascript:alert(1)"} {
		if _, err := validForgeURL(bad); keyOf(err) != KeyForgeURL {
			t.Errorf("%q : %v", bad, err)
		}
	}
}

// TestCleanByKind : un dépôt exige au moins une référence, un serveur une référence
// d'hôte valide ; la nature inconnue est refusée.
func TestCleanByKind(t *testing.T) {
	if _, err := clean(KindRepo, Input{Name: "a"}); keyOf(err) != KeyRefsMissing {
		t.Errorf("dépôt sans référence : %v", err)
	}
	if in, err := clean(KindRepo, Input{Name: " a ", Branches: []string{"main"}}); err != nil || in.Name != "a" || in.HostRef != "" {
		t.Errorf("dépôt : %+v %v", in, err)
	}
	if _, err := clean(KindHost, Input{Name: "a"}); keyOf(err) != KeyHostRefInvalid {
		t.Errorf("serveur sans hôte : %v", err)
	}
	if in, err := clean(KindHost, Input{Name: "a", HostRef: "Srv", ForgeURL: "https://x/y", Branches: []string{"main"}}); err != nil ||
		in.HostRef != "srv" || in.ForgeURL != "" || in.Branches != nil {
		t.Errorf("serveur : %+v %v", in, err)
	}
	if _, err := clean("vm", Input{Name: "a"}); keyOf(err) != KeyKindInvalid {
		t.Errorf("nature inconnue : %v", err)
	}
	// Un conteneur ne garde que nom, description et étiquettes : sa référence est son
	// identité, tenue par l'agent.
	if in, err := clean(KindContainer, Input{Name: "a", HostRef: "x", ForgeURL: "https://x/y", Branches: []string{"main"}}); err != nil ||
		in.HostRef != "" || in.ForgeURL != "" || in.Branches != nil {
		t.Errorf("conteneur : %+v %v", in, err)
	}
	if _, err := ParseKind(string(KindContainer)); keyOf(err) != KeyKindInvalid {
		t.Error("un conteneur ne se crée pas à la main")
	}
	if _, err := clean(KindRepo, Input{Name: "", Branches: []string{"main"}}); keyOf(err) != KeyNameInvalid {
		t.Errorf("nom vide : %v", err)
	}
	if _, err := clean(KindRepo, Input{Name: "a", Description: strings.Repeat("d", 2001), Branches: []string{"main"}}); keyOf(err) != KeyDescription {
		t.Errorf("description trop longue : %v", err)
	}
	if _, err := ParseKind("x"); keyOf(err) != KeyKindInvalid {
		t.Error("ParseKind")
	}
}
