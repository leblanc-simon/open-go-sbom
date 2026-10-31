package locales

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
)

func languages(t *testing.T) []string {
	t.Helper()
	files, err := fs.Glob(FS, "*.yaml")
	if err != nil || len(files) < 2 {
		t.Fatalf("fichiers de traduction : %v, %v", files, err)
	}
	var out []string
	for _, f := range files {
		out = append(out, strings.TrimSuffix(f, ".yaml"))
	}
	return out
}

// TestEveryLanguageHasTheSameKeys fait échouer les tests dès qu'une clé manque dans une
// langue, ou qu'une langue en a une de trop.
func TestEveryLanguageHasTheSameKeys(t *testing.T) {
	ref, err := Messages(Reference)
	if err != nil || len(ref) == 0 {
		t.Fatalf("%s.yaml : %v", Reference, err)
	}
	for _, lang := range languages(t) {
		msgs, err := Messages(lang)
		if err != nil {
			t.Fatal(err)
		}
		for k := range ref {
			if _, ok := msgs[k]; !ok {
				t.Errorf("%s.yaml : clé %s manquante", lang, k)
			}
		}
		for k, v := range msgs {
			if _, ok := ref[k]; !ok {
				t.Errorf("%s.yaml : clé %s absente de %s.yaml", lang, k, Reference)
			}
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s.yaml : clé %s vide", lang, k)
			}
		}
	}
}

// TestKeysAvoidReservedNames : go-i18n prend pour un message toute table qui contient un
// de ses noms réservés ; ses clés disparaîtraient alors en silence.
func TestKeysAvoidReservedNames(t *testing.T) {
	reserved := []string{"description", "hash", "id", "translation", "leftdelim", "rightdelim"}
	keys, err := Keys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		for _, p := range strings.Split(k, ".") {
			if slices.Contains(reserved, p) {
				t.Errorf("%s emploie le nom réservé %q", k, p)
			}
		}
	}
}

func TestPluralMessagesCountAsOneKey(t *testing.T) {
	tree := map[string]any{"a": map[string]any{"one": "x", "other": "y"}, "b": map[string]any{"c": "z"}}
	out := map[string]string{}
	if err := flatten("", tree, out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != pluralMarker || out["b.c"] != "z" || len(out) != 2 {
		t.Fatalf("flatten = %v", out)
	}
	if err := flatten("", map[string]any{"n": 3}, map[string]string{}); err == nil {
		t.Fatal("valeur non textuelle acceptée")
	}
}
