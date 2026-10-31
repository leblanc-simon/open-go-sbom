// Package webtest aide les tests de l'interface à vérifier une page rendue : règles
// d'accessibilité vérifiables automatiquement (RGAA / WCAG 2.1 AA) et absence de script
// ou de style en ligne (CSP stricte). Chaque écran les appelle sur ses pages :
//
//	rec := httptest.NewRecorder()
//	router.ServeHTTP(rec, req)
//	webtest.AssertAccessible(t, rec.Body.Bytes())
//	webtest.AssertNoInlineCode(t, rec.Body.Bytes())
//
// Les fonctions Check* renvoient les écarts au lieu d'échouer, pour tester l'assistant
// lui-même. Ces contrôles ne remplacent pas l'audit manuel qui clôt chaque lot à écran.
package webtest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// AssertAccessible fait échouer le test pour chaque écart de CheckAccessibility.
func AssertAccessible(t testing.TB, page []byte) {
	t.Helper()
	for _, p := range CheckAccessibility(page) {
		t.Errorf("accessibilité : %s", p)
	}
}

// AssertNoInlineCode fait échouer le test pour chaque écart de CheckNoInlineCode.
func AssertNoInlineCode(t testing.TB, page []byte) {
	t.Helper()
	for _, p := range CheckNoInlineCode(page) {
		t.Errorf("CSP : %s", p)
	}
}

// CheckAccessibility vérifie : langue du document, titre non vide, un seul h1, ordre des
// titres sans saut, identifiants uniques, libellé de chaque champ, texte alternatif de
// chaque image, nom accessible des liens et boutons, et lien d'évitement en premier
// élément focalisable, vers une cible qui existe.
func CheckAccessibility(page []byte) []string {
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return []string{"HTML illisible : " + err.Error()}
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	root := find(doc, func(n *html.Node) bool { return n.DataAtom == atom.Html })
	if root == nil || strings.TrimSpace(attr(root, "lang")) == "" {
		add("<html> sans attribut lang")
	}
	if title := find(doc, is(atom.Title)); title == nil || strings.TrimSpace(text(title)) == "" {
		add("<title> absent ou vide")
	}

	ids := map[string]bool{}
	labelled := map[string]bool{}
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if id := attr(n, "id"); id != "" {
			if ids[id] {
				add("identifiant %q en double", id)
			}
			ids[id] = true
		}
		if n.DataAtom == atom.Label {
			if f := attr(n, "for"); f != "" {
				labelled[f] = true
			}
		}
	})

	var h1, lastLevel int
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if level := headingLevel(n); level > 0 {
			if level == 1 {
				h1++
			}
			if lastLevel > 0 && level > lastLevel+1 {
				add("titre <h%d> après <h%d> : niveau sauté", level, lastLevel)
			}
			lastLevel = level
			if strings.TrimSpace(text(n)) == "" {
				add("<h%d> vide", level)
			}
		}
		switch n.DataAtom {
		case atom.Img:
			if _, ok := attrOK(n, "alt"); !ok {
				add("<img src=%q> sans attribut alt", attr(n, "src"))
			}
		case atom.Input, atom.Select, atom.Textarea:
			typ := strings.ToLower(attr(n, "type"))
			if typ == "hidden" || typ == "submit" || typ == "button" || typ == "reset" || typ == "image" {
				return
			}
			if !hasLabel(n, labelled) {
				add("champ <%s name=%q> sans libellé", n.Data, attr(n, "name"))
			}
		case atom.A:
			if _, ok := attrOK(n, "href"); ok && accessibleName(n) == "" {
				add("lien %q sans nom accessible", attr(n, "href"))
			}
		case atom.Button:
			if accessibleName(n) == "" {
				add("bouton sans nom accessible")
			}
		}
	})
	if h1 != 1 {
		add("%d titres <h1>, un seul attendu", h1)
	}

	first := find(doc, focusable)
	switch {
	case first == nil:
		add("aucun élément focalisable : lien d'évitement absent")
	case first.DataAtom != atom.A || !strings.HasPrefix(attr(first, "href"), "#"):
		add("le premier élément focalisable n'est pas un lien d'évitement (<a href=\"#…\">)")
	case !ids[strings.TrimPrefix(attr(first, "href"), "#")]:
		add("le lien d'évitement vise %q, absent de la page", attr(first, "href"))
	}
	return problems
}

// CheckNoInlineCode signale tout script ou style en ligne : élément <style>, attribut
// style, <script> sans src, gestionnaire on*, URL javascript:.
func CheckNoInlineCode(page []byte) []string {
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return []string{"HTML illisible : " + err.Error()}
	}
	var problems []string
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		switch n.DataAtom {
		case atom.Style:
			problems = append(problems, "élément <style> en ligne")
		case atom.Script:
			if attr(n, "src") == "" {
				problems = append(problems, "élément <script> en ligne")
			}
		}
		for _, a := range n.Attr {
			key := strings.ToLower(a.Key)
			switch {
			case key == "style":
				problems = append(problems, fmt.Sprintf("attribut style sur <%s>", n.Data))
			case strings.HasPrefix(key, "on"):
				problems = append(problems, fmt.Sprintf("gestionnaire %s sur <%s>", key, n.Data))
			case (key == "href" || key == "src" || key == "action" || key == "formaction") &&
				strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.Val)), "javascript:"):
				problems = append(problems, fmt.Sprintf("URL javascript: sur <%s>", n.Data))
			}
		}
	})
	return problems
}

func walk(n *html.Node, fn func(*html.Node)) {
	fn(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, fn)
	}
}

func find(n *html.Node, pred func(*html.Node) bool) *html.Node {
	if pred(n) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if f := find(c, pred); f != nil {
			return f
		}
	}
	return nil
}

func is(a atom.Atom) func(*html.Node) bool {
	return func(n *html.Node) bool { return n.Type == html.ElementNode && n.DataAtom == a }
}

func attrOK(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func attr(n *html.Node, key string) string {
	v, _ := attrOK(n, key)
	return v
}

func text(n *html.Node) string {
	var b strings.Builder
	walk(n, func(c *html.Node) {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	})
	return b.String()
}

func headingLevel(n *html.Node) int {
	switch n.DataAtom {
	case atom.H1:
		return 1
	case atom.H2:
		return 2
	case atom.H3:
		return 3
	case atom.H4:
		return 4
	case atom.H5:
		return 5
	case atom.H6:
		return 6
	}
	return 0
}

// accessibleName approche le nom accessible : aria-label, aria-labelledby, title, texte
// ou texte alternatif des images contenues.
func accessibleName(n *html.Node) string {
	for _, k := range []string{"aria-label", "aria-labelledby", "title"} {
		if v := strings.TrimSpace(attr(n, k)); v != "" {
			return v
		}
	}
	var b strings.Builder
	walk(n, func(c *html.Node) {
		switch {
		case c.Type == html.TextNode:
			b.WriteString(c.Data)
		case c.Type == html.ElementNode && c.DataAtom == atom.Img:
			b.WriteString(attr(c, "alt"))
		}
	})
	return strings.TrimSpace(b.String())
}

func hasLabel(n *html.Node, labelled map[string]bool) bool {
	if strings.TrimSpace(attr(n, "aria-label")) != "" || strings.TrimSpace(attr(n, "aria-labelledby")) != "" {
		return true
	}
	if id := attr(n, "id"); id != "" && labelled[id] {
		return true
	}
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && p.DataAtom == atom.Label {
			return true
		}
	}
	return false
}

// focusable dit si un élément reçoit le focus au clavier dans l'ordre naturel.
func focusable(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}
	if _, hidden := attrOK(n, "hidden"); hidden {
		return false
	}
	if attr(n, "tabindex") == "-1" {
		return false
	}
	switch n.DataAtom {
	case atom.A:
		_, ok := attrOK(n, "href")
		return ok
	case atom.Button, atom.Select, atom.Textarea:
		_, disabled := attrOK(n, "disabled")
		return !disabled
	case atom.Input:
		_, disabled := attrOK(n, "disabled")
		return !disabled && strings.ToLower(attr(n, "type")) != "hidden"
	}
	_, ok := attrOK(n, "tabindex")
	return ok
}
