# 0009 — Fonctions de gabarit dépendantes de la requête : un jeu de gabarits par langue

- Statut : Accepté
- Date : 2026-10-31
- Lot : T01

## Contexte

Les gabarits `html/template` ont besoin de fonctions qui dépendent de la requête : la
traduction (`T`, `Tn`, liées à la langue) et le jeton CSRF (`csrfField`). Or les fonctions
d'un jeu de gabarits se fixent avant son analyse, et `html/template` interdit de cloner un
jeu déjà exécuté. Le § 14 de l'architecture laissait deux options : cloner par requête un
jeu jamais exécuté, ou passer le traducteur et le jeton dans les données de la page.
Critères : coût par requête, simplicité des gabarits, impossibilité d'oublier la
traduction.

Mesures (page d'accueil complète : layout, en-tête, pied de page, contenu ; Go 1.26.10,
Intel Xeon 2,8 GHz, 4 cœurs ; `go test -bench . ./internal/render/`) :

| Stratégie | Temps par rendu | Mémoire | Allocations |
| --- | --- | --- | --- |
| Clonage par requête + `Funcs` + exécution | 243 µs | 59 Kio | 995 |
| Jeu par langue préparé au démarrage | 69 µs | 11 Kio | 284 |

Le clonage coûte cher parce que `html/template` copie les arbres et refait l'échappement
contextuel à la première exécution de chaque clone, soit à chaque requête ; le coût croît
avec la taille des gabarits.

Passer le traducteur dans les données (`{{.Page.T "clé"}}`) ne coûte rien de plus, mais
le point courant change dans `range`, `with` et les partials : il faut `$` ou repasser la
page à chaque partial, et un partial qui reçoit autre chose que la page ne peut plus
traduire. C'est précisément là qu'une chaîne finirait écrite en dur.

## Décision

- Au démarrage, `internal/render` analyse une fois le layout et les partials, puis
  construit **un jeu de gabarits par page et par langue** : clone du jeu de base, fonctions
  `T` et `Tn` liées au localiseur de la langue, page analysée, échappement forcé (une
  erreur d'échappement empêche le démarrage). Le rendu choisit le jeu par la langue de la
  requête et l'exécute : aucun clonage par requête.
- Ce qui dépend vraiment de la requête passe par `render.Page`, que `Render` remplit
  lui-même depuis la requête (langue, thème, jeton CSRF, identifiant de requête,
  version) : un handler ne peut pas l'oublier. Le champ CSRF s'écrit
  `{{csrfField .Page.CSRFToken}}`.
- Les futures fonctions de format qui dépendent de la langue (`format.*` : dates,
  nombres) suivent le même modèle.

## Conséquences

- `T` est disponible partout, partials compris, sans contexte à transmettre.
- La mémoire croît avec le nombre de langues × pages (quelques Kio par jeu) : négligeable
  pour deux langues.
- Une page qui oublie `csrfField` dans un formulaire échoue en 403 dès son premier test,
  ce qui est visible, contrairement à une traduction oubliée.

## Alternatives écartées

- Clonage par requête : 3,5 fois plus lent, 5 fois plus d'allocations, coût croissant.
- Traducteur dans les données : ergonomie des partials, risque d'oubli de la traduction.
- Fonction `T` qui lirait la langue dans une variable partagée : état global mutable,
  incompatible avec des requêtes concurrentes.
