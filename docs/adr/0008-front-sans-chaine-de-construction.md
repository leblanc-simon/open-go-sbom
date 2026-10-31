# 0008 — Interface sans chaîne de construction front

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

L'interface est rendue côté serveur ; le client affiche, sans logique métier. Une chaîne
npm ajouterait une seconde gestion de dépendances, une surface d'attaque de chaîne
d'approvisionnement et une étape de construction.

## Décision

- Gabarits `html/template` embarqués, un modèle de vue typé par écran.
- CSS natif imbriqué (`tokens.css`, `base.css`, un fichier par composant et par écran),
  concaténé au démarrage en une feuille à l'URL empreinte.
- JavaScript en modules ES natifs, un par écran, en amélioration progressive ; chaque page
  fonctionne sans JS ; libellés reçus traduits via des attributs `data-`.
- CSP stricte : aucun script ni style en ligne ; polices auto-hébergées.

## Conséquences

Pas de npm, pas de bundler, pas de transpilation : le CSS et le JS visent les navigateurs
à jour (imbrication CSS native, modules ES). Les tests Go analysent le HTML rendu.

## Alternatives écartées

- Framework SPA : logique déportée dans le client, double contrat, chaîne npm.
- htmx : une dépendance JS de plus ; les besoins d'amélioration progressive sont couverts
  par quelques modules.
