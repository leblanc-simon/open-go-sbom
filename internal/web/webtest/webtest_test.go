package webtest

import (
	"strings"
	"testing"
)

const good = `<!doctype html><html lang="fr"><head><title>Accueil</title></head><body>
<a class="skip-link" href="#main">Aller au contenu</a>
<header><a href="/"><img src="/logo.svg" alt=""><span>open-go-sbom</span></a>
<button type="button" hidden>Thème</button></header>
<main id="main" tabindex="-1"><h1>Titre</h1><h2>Section</h2>
<form><label for="q">Recherche</label><input id="q" name="q">
<label>Nom <input name="n"></label><input type="hidden" name="csrf_token" value="x">
<input name="z" aria-label="Zone"><select name="s" aria-labelledby="q"></select>
<button type="submit">Envoyer</button></form>
<a href="/x" aria-label="Fermer"><svg aria-hidden="true"></svg></a></main></body></html>`

func TestCheckAccessibilityAcceptsAGoodPage(t *testing.T) {
	if got := CheckAccessibility([]byte(good)); len(got) != 0 {
		t.Fatalf("écarts sur une page correcte : %v", got)
	}
	AssertAccessible(t, []byte(good))
}

func TestCheckAccessibilityFindsProblems(t *testing.T) {
	cases := map[string]struct {
		from, to string
		want     string
	}{
		"sans langue":             {`<html lang="fr">`, `<html>`, "lang"},
		"titre vide":              {`<title>Accueil</title>`, `<title> </title>`, "<title>"},
		"deux h1":                 {`<h2>Section</h2>`, `<h1>Section</h1>`, "2 titres <h1>"},
		"aucun h1":                {`<h1>Titre</h1>`, `<h2>Titre</h2>`, "0 titres <h1>"},
		"niveau sauté":            {`<h2>Section</h2>`, `<h3>Section</h3>`, "niveau sauté"},
		"titre vide h2":           {`<h2>Section</h2>`, `<h2></h2>`, "<h2> vide"},
		"image sans alt":          {`alt=""`, ``, "sans attribut alt"},
		"champ sans libellé":      {`<label for="q">Recherche</label>`, ``, `champ <input name="q">`},
		"identifiant en double":   {`<input name="z"`, `<input id="q" name="z"`, "en double"},
		"lien sans nom":           {`aria-label="Fermer"`, ``, "sans nom accessible"},
		"bouton sans nom":         {`<button type="submit">Envoyer</button>`, `<button type="submit"></button>`, "bouton sans nom"},
		"pas de lien d'évitement": {`<a class="skip-link" href="#main">Aller au contenu</a>`, ``, "lien d'évitement"},
		"évitement sans cible":    {`id="main"`, `id="contenu"`, "absent de la page"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			page := strings.Replace(good, c.from, c.to, 1)
			if page == good {
				t.Fatal("remplacement sans effet")
			}
			got := strings.Join(CheckAccessibility([]byte(page)), " | ")
			if !strings.Contains(got, c.want) {
				t.Fatalf("écarts = %q, attendu %q", got, c.want)
			}
		})
	}
}

func TestCheckNoInlineCode(t *testing.T) {
	if got := CheckNoInlineCode([]byte(`<html><head><script type="module" src="/a.js"></script>` +
		`<link rel="stylesheet" href="/a.css"></head><body><a href="/x">x</a></body></html>`)); len(got) != 0 {
		t.Fatalf("écarts sur une page correcte : %v", got)
	}
	cases := map[string]string{
		"<style>":     `<style>p{}</style>`,
		"<script>":    `<script>alert(1)</script>`,
		"style":       `<p style="color:red">x</p>`,
		"onclick":     `<button onclick="x()">x</button>`,
		"javascript:": `<a href=" JavaScript:alert(1)">x</a>`,
	}
	for want, snippet := range cases {
		got := strings.Join(CheckNoInlineCode([]byte(`<html><body>`+snippet+`</body></html>`)), " | ")
		if !strings.Contains(strings.ToLower(got), strings.ToLower(strings.Trim(want, "<>"))) {
			t.Errorf("%s non détecté : %q", want, got)
		}
	}
}
