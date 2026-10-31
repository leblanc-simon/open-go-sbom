# 0019 — Mesures de référence et autoanalyse en CI

- Statut : Accepté
- Date : 2026-10-31
- Lot : T06

## Contexte

T06 écrit `docs/benchmarks.md` (machine de référence, protocole, jeu synthétique réutilisé
par T09, T10, T11 et T21) et ajoute à la CI l'analyse des SBOM des trois binaires, avec
échec sur une vulnérabilité KEV. La CI n'a pas la base Grype (3,2 Gio installée) ; les
tests qui en dépendent sont étiquetés `grypedb`.

## Décision

- **Jeu synthétique** : paquet `internal/benchdata` (non importé par les binaires),
  `Generate` écrit en SQL `generate_series`, sous la RLS de l'organisation, 1 000 projets,
  1 million de liens, 60 013 composants, 5 000 vulnérabilités et environ 75 000 constats en
  moins d'une minute ; distribution déterministe documentée dans le paquet.
  `SyntheticCycloneDX(n, variante)` produit un SBOM de n composants (dont dix paquets
  réellement vulnérables) dont chaque variante est un inventaire distinct.
- **Protocole** : 95e centile sur au moins 20 passages, cache froid (premier passage après
  l'ouverture de la base Grype ou un `ANALYZE` neuf) et chaud, RLS active (rôle
  d'exécution), base jetable de `dbtest` ; résultats consignés dans
  `docs/benchmarks.md` avec la machine qui les a produits.
- **Cibles mesurables sans la base Grype** (`make bench`, `LOTOR_BENCH=1`) et **avec**
  (`make test-grypedb`, `LOTOR_TEST_GRYPEDB_DIR`).
- **Autoanalyse** : `make sbom` produit `bin/<binaire>.cdx.json` par la commande `syft`,
  `make selfscan` les analyse par la commande `grype --by-cve` et échoue si une
  correspondance porte `knownExploited` ; les deux commandes sont lancées par
  `go run …@<version de go.mod>` : mêmes versions que les bibliothèques, sommes vérifiées
  par la base de sommes Go, aucune action GitHub tierce. Job `selfscan` en CI, base
  téléchargée à chaque passage.

## Conséquences

- La publication des SBOM comme artefacts de version attend la chaîne de publication
  (T26) ; la CI les produit et les analyse à chaque build sans les conserver.
- Le job `selfscan` dépend du réseau (téléchargement de la base, environ 200 Mio) : une
  indisponibilité d'Anchore le fait échouer, sans masquer les autres vérifications.
- Les mesures de ce lot ont été faites dans l'environnement de réalisation (4 cœurs,
  15 Gio), moins puissant que la machine de référence : une cible tenue ici l'est a
  fortiori sur la référence.

## Alternatives écartées

- **Actions `anchore/sbom-action` et `anchore/scan-action`** : dépendances tierces de CI à
  épingler et à faire valider, pour le même résultat que les commandes aux versions déjà
  validées du § 5.
- **Programme d'autoanalyse maison** (`cmd/…`) : un quatrième binaire pour ce que les
  commandes d'Anchore font déjà.
- **Jeu de données en fichiers (dump)** : volumineux, à régénérer à chaque migration ; le
  générateur suit le schéma.
