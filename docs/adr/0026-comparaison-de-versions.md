# 0026 — Comparaison de versions par écosystème et plages vers

- Statut : Accepté
- Date : 2026-10-31
- Lot : T09

## Contexte

La recherche filtre les versions d'un paquet par une plage `vers`, et la fiche composant
trie ses versions : il faut comparer selon chaque écosystème (npm, Maven, PEP 440,
RubyGems, Go, Debian, RPM, Alpine, semver générique). Le § 3 prévoit `internal/version` et
son adaptateur `version/grypeversion` vers les comparateurs de Grype, déjà dans le graphe
(§ 5) ; la fiche demande un analyseur de plages `vers` maison.

## Décision

- `internal/version` définit les **règles** (`Scheme` : npm, maven, pypi, gem, golang,
  deb, rpm, alpine, semver), la règle d'un type de purl (`ForPURLType` : tout type inconnu
  se compare en semver générique), l'interface `Comparer` (−1, 0, 1, ou une erreur
  enveloppant `ErrNotComparable`), le tri (`Sort` : versions illisibles à part) et les
  plages `vers` (`ParseVers`, `Range.Contains`). Il n'importe pas Grype.
- `version/grypeversion` implémente `Comparer` avec `grype/version` (format par règle :
  npm et semver → `SemanticFormat`, etc.), avec deux corrections, chacune couverte par un
  test :
  - le résultat combine les deux sens de comparaison (`signe(a?b) − signe(b?a)`) : le
    comparateur dpkg renvoie une différence et non un signe, et celui de PEP 440 n'est pas
    antisymétrique sur les versions locales (`0+00` contre `0`, trouvé par fuzzing) ;
  - une époque rpm absente vaut 0 des deux côtés (`0:` ajouté) : Grype ignore une époque
    présente d'un seul côté, règle utile pour la correspondance avec une base, fausse pour
    ordonner deux versions d'un inventaire.
- **Plages vers** (spécification purl `VERSION-RANGE-SPEC`) : `vers:<schéma>/<contraintes>`,
  espaces ignorés, schéma en minuscules, comparateurs `=` (implicite), `!=`, `<`, `<=`, `>`,
  `>=`, `*` seul ; versions décodées pour cent ; à la lecture, chaque version doit se lire
  dans son schéma, aucune ne doit se répéter, et les contraintes sont triées. L'appartenance
  suit l'algorithme de la spécification (égalités d'abord, puis intervalles). Une plage ne
  s'applique qu'à un purl de même règle (`vers:npm` pour `pkg:npm`). Bornes : 1 024 octets,
  64 contraintes.
- Une version de l'inventaire **illisible** dans son écosystème (« latest », date libre)
  n'est jamais rangée en silence dans ou hors d'une plage : la recherche la signale avec
  ses occurrences, la fiche composant la place après les versions triées.

## Conséquences

- Les règles de Grype évoluent avec ses versions : les tables de comparaison par
  écosystème (`grypeversion_test.go`) et les fuzzers des deux paquets détectent un
  changement de comportement à la montée de version.
- Maven lit toute chaîne (un qualificatif seul se classe avant les versions) : « latest »
  n'y est pas illisible.

## Alternatives écartées

- **Une bibliothèque `vers` tierce** : nouvelle dépendance, et la comparaison resterait à
  brancher sur les règles de Grype que l'analyse utilise déjà.
- **Comparaison en SQL** (tri lexical, découpage en entiers) : faux pour les pré-versions,
  époques, `~` Debian, qualificatifs Maven, PEP 440.
- **Comparateurs de Grype sans correction** : tri instable (dpkg) et ordre incohérent
  (PEP 440, époques rpm).
