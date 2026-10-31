// Package web embarque les gabarits et les fichiers statiques de l'interface.
//
//	templates/layout.html     squelette de page (gabarit « layout »)
//	templates/partials/*.html  en-tête, navigation, pied de page…
//	templates/<écran>/*.html   une page par fichier, qui définit « content »
//	static/css/                tokens.css, fonts.css, base.css, components/*.css,
//	                           screens/*.css : concaténés en une feuille (internal/render)
//	static/js/                 modules ES, un par écran
//	static/fonts/, static/img/ polices auto-hébergées (avec leur licence), images
//
// Les gabarits ne font que de l'affichage : aucune chaîne visible en dur (clés de
// traduction), aucun script ni style en ligne.
package web

import (
	"embed"
	"io/fs"
)

//go:embed templates
var templates embed.FS

//go:embed static
var static embed.FS

// Templates renvoie les gabarits, racine au dossier templates.
func Templates() (fs.FS, error) { return fs.Sub(templates, "templates") }

// Static renvoie les fichiers statiques, racine au dossier static.
func Static() (fs.FS, error) { return fs.Sub(static, "static") }
