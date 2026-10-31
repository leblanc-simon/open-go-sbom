// Package render charge les gabarits, les fonctions de gabarit et l'empreinte des
// fichiers statiques, et rend les pages de l'interface.
//
// # Gabarits
//
// web/templates/layout.html définit « layout » ; partials/*.html les morceaux communs ;
// chaque page (« home/index » pour home/index.html) définit « content ». Au démarrage,
// New analyse tout, construit un jeu par page et par langue, et force l'échappement :
// un gabarit invalide empêche le démarrage. Fonctions disponibles :
//
//	{{T "home.heading"}}                       traduction (paires clé, valeur ou table)
//	{{Tn "projects.count" .N}}                 pluriel
//	{{asset "js/search.js"}}                   URL à empreinte d'un fichier statique
//	{{csrfField .Page.CSRFToken}}              champ caché CSRF d'un formulaire
//
// T et Tn sont liées à la langue du jeu de gabarits, si bien que la traduction est
// disponible partout, partials compris ; ce qui dépend de la requête (jeton CSRF,
// thème…) passe par Page (ADR 0009).
//
// # Rendu
//
// Un handler construit un modèle de vue qui embarque Page, et appelle :
//
//	rd.Render(w, r, http.StatusOK, "home/index", &homeView{Page: render.Page{TitleKey: "home.title"}})
//	rd.Error(w, r, http.StatusNotFound)
//
// # Fichiers statiques
//
// Assets concatène les feuilles (tokens.css, fonts.css, base.css, components/*.css,
// screens/*.css) en css/app.css et sert tous les fichiers sous /static/<empreinte>/.
// Les url() d'une feuille sont relatives à static/css/.
package render
