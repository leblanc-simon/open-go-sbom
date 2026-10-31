package locale

import (
	"context"
	"sync"
	"testing"
	"testing/fstest"

	"golang.org/x/text/language"

	"leblanc.io/open-go-sbom/locales"
)

func catalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNew(t *testing.T) {
	c := catalog(t)
	if c.Default() != language.French {
		t.Fatalf("Default = %v", c.Default())
	}
	langs := c.Languages()
	if len(langs) != 2 || langs[0] != language.French || langs[1] != language.English {
		t.Fatalf("Languages = %v", langs)
	}
	if _, err := New(locales.FS, ".", "de"); err == nil {
		t.Fatal("langue par défaut sans traductions acceptée")
	}
	if _, err := New(locales.FS, ".", "!!"); err == nil {
		t.Fatal("langue par défaut invalide acceptée")
	}
	if _, err := New(fstest.MapFS{"x.txt": {}}, ".", "fr"); err == nil {
		t.Fatal("dossier sans traductions accepté")
	}
	en, err := New(locales.FS, ".", "en")
	if err != nil || en.Languages()[0] != language.English {
		t.Fatalf("langue par défaut anglaise : %v, %v", err, en)
	}
}

func TestMatch(t *testing.T) {
	c := catalog(t)
	cases := []struct {
		pref string
		want language.Tag
		ok   bool
	}{
		{"fr", language.French, true},
		{"en", language.English, true},
		{"en-GB", language.English, true},
		{"fr-CA", language.French, true},
		{"de-DE,de;q=0.9,en;q=0.8", language.English, true},
		{"en;q=0.5, fr;q=0.9", language.French, true},
		{"de", language.French, false},
		{"", language.French, false},
		{"pas une langue !", language.French, false},
		{"*", language.French, false},
	}
	for _, tc := range cases {
		got, ok := c.Match(tc.pref)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Match(%q) = %v, %v ; attendu %v, %v", tc.pref, got, ok, tc.want, tc.ok)
		}
	}
	long := make([]byte, maxPreferenceLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, ok := c.Match(string(long)); ok {
		t.Error("préférence démesurée analysée")
	}
}

// TestResolveFollowsArchitectureOrder : ?lang=, compte, Accept-Language, organisation,
// défaut (§ 18).
func TestResolveFollowsArchitectureOrder(t *testing.T) {
	c := catalog(t)
	cases := []struct {
		name                        string
		query, account, accept, org string
		want                        language.Tag
	}{
		{"paramètre d'abord", "en", "fr", "fr", "fr", language.English},
		{"puis le compte", "", "en", "fr", "fr", language.English},
		{"puis Accept-Language", "", "", "en-US,en;q=0.9", "fr", language.English},
		{"puis l'organisation", "", "", "", "en", language.English},
		{"paramètre inconnu ignoré", "xx", "", "en", "", language.English},
		{"Accept-Language sans langue disponible", "", "", "de,it", "en", language.English},
		{"défaut de l'instance", "", "", "", "", language.French},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Resolve(tc.query, tc.account, tc.accept, tc.org); got != tc.want {
				t.Fatalf("Resolve = %v, attendu %v", got, tc.want)
			}
		})
	}
}

// TestEveryKeyTranslates vérifie, par go-i18n lui-même, que chaque clé se traduit dans
// chaque langue : une table mal formée y serait ignorée en silence.
func TestEveryKeyTranslates(t *testing.T) {
	c := catalog(t)
	keys, err := locales.Keys()
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range c.Languages() {
		loc := c.Localizer(tag)
		for _, k := range keys {
			if got := loc.T(k, map[string]any{"Version": "1", "Code": 404, "RequestID": "r", "Max": 100}); got == k || got == "" {
				t.Errorf("%v : %s non traduit", tag, k)
			}
		}
	}
	if c.Localizer(language.German) != c.Localizer(language.French) {
		t.Error("une langue indisponible ne retombe pas sur la langue par défaut")
	}
	if got := c.Localizer(language.English).T("home.title"); got != "Home" {
		t.Errorf("home.title en anglais = %q", got)
	}
}

func TestLocalizersAreSafeForConcurrentUse(t *testing.T) {
	c := catalog(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				_ = c.Localizer(language.English).T("footer.version", map[string]any{"Version": "x"})
				_ = c.Localizer(language.French).T("home.heading")
			}
		})
	}
	wg.Wait()
}

func TestContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("localiseur trouvé dans un contexte vide")
	}
	loc := catalog(t).Localizer(language.French)
	got, ok := FromContext(NewContext(context.Background(), loc))
	if !ok || got != loc {
		t.Fatal("localiseur perdu")
	}
}
