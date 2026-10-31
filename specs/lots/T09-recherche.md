# T09 — Recherche transverse

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T06 | À faire |

## Objectif

Répondre en moins de 2 s à « qui utilise ce composant, cette version, cette plage de
versions ? » et « qui est touché par cette CVE ? », à l'écran comme par l'API.

## Périmètre

**Inclus**

- `internal/version` : comparaison par écosystème (npm, Maven, PEP 440, RubyGems, Go,
  Debian, RPM, Alpine, semver générique) via l'adaptateur `grypeversion`, et analyseur de
  plages `vers` maison.
- `internal/search` : détection du type de requête (§ 13), filtres, plan d'exécution,
  pagination par projet, export CSV et JSON en flux.
- Index : extension `pg_trgm` et index trigramme sur le nom, index sur
  (`org_id`, `purl_base`), sur les composants des ensembles d'inventaire, sur `ref_current`
  et sur `findings` par vulnérabilité.
- Écran de recherche : barre unique, rappel du type détecté, filtres en formulaire `GET`,
  résultats groupés par projet, boutons d'export.
- Jetons d'accès personnels (`ogs_pat_`) : création et révocation depuis le profil, lecture
  seule, limités aux organisations du compte ; route `GET /api/v1/orgs/{org}/search`.
- Banc d'essai `make bench-search` sur le jeu de données synthétique de T06.

**Exclu** : recherche à une date passée (T21), recherche par licence enrichie par Grant (T20).

## Conception

- Une plage `vers` n'est acceptée qu'avec un `purl_base` exact : le SQL réduit l'ensemble à
  ce paquet dans l'organisation (un nombre borné de versions), puis Go filtre les versions
  avec le comparateur de l'écosystème et pagine. Une plage n'est jamais comparée comme du
  texte, et une recherche approchée par nom refuse une plage avec un message explicite.
- Une version non comparable dans son écosystème est signalée dans le résultat plutôt
  qu'ignorée en silence.
- L'export lit en flux et écrit en flux : mémoire constante quel que soit le volume.
- La création de l'extension `pg_trgm` est documentée pour les bases gérées.

## Livrables

Paquets, migrations, écran, route d'API, jetons personnels, banc d'essai, section
« Recherche » de la documentation utilisateur.

## Critères d'acceptation

- [ ] `vers:npm/<4.17.21` sur `pkg:npm/lodash` ne renvoie que les versions inférieures.
- [ ] `CVE-2021-44228` renvoie les projets touchés avec statut et version corrigée.
- [ ] Le SHA-256 d'un fichier connu d'un SBOM d'exemple renvoie le composant et ses projets.
- [ ] Les filtres sont reflétés dans l'URL ; une URL partagée redonne le même résultat.
- [ ] L'API renvoie exactement les mêmes résultats que l'écran.
- [ ] Banc d'essai : moins de 2 s au 95e centile sur 1 000 projets et 1 million de liens,
      selon `docs/benchmarks.md` (mesure consignée).
- [ ] Un jeton personnel révoqué est refusé ; il ne donne jamais plus de droits que son
      propriétaire.

## Tests attendus

Fuzzing de l'analyseur de requête et de `vers`. Tables de comparaison de versions par
écosystème. Intégration sur un petit jeu connu ; isolement entre organisations.

## Points à trancher

Aucun.

## Journal

_À remplir pendant la réalisation._
