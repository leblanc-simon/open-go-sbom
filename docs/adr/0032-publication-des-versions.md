# 0032 — Publication des versions : étiquette, workflow et fichiers livrés

- Statut : Accepté (à relire par l'utilisateur)
- Date : 2026-10-31
- Lot : T11

## Contexte

La fiche de T11 décide une préversion `v0.1.0` publiée sur GitHub Releases : étiquette,
binaires des trois rôles et sommes de contrôle. Il faut fixer comment une version est
construite (reproductible, identique en local et en CI), ce qu'elle contient, et qui la
publie. La session de réalisation ne peut pas pousser d'étiquette (mandataire git) : la
pose reste un geste de l'utilisateur, qui doit suffire à tout déclencher.

## Décision

- **Déclencheur** : une étiquette `v*` poussée. Le workflow `.github/workflows/release.yml`
  (un seul job, `permissions: contents: write` sur ce job seulement, `{}` au niveau du
  workflow ; actions épinglées par SHA comme `ci.yml`) vérifie que l'étiquette désigne un
  commit de `main`, extrait les notes de la section de la version dans `CHANGELOG.md`
  (échec si elle manque), rejoue les tests unitaires, construit, vérifie les sommes et crée
  la version par `gh release create --prerelease --verify-tag`.
- **Préversions seulement** jusqu'à T26 : le workflow refuse une version stable (ni `v0.*`
  ni suffixe `-…`) ; T26 lèvera ce garde-fou pour la v1.0.
- **Construction** par `scripts/release.sh`, appelé par `make release VERSION=vX.Y.Z
  RELEASE_DIR=…` en local comme en CI : pour linux amd64 et arm64, une archive
  `<rôle>_<X.Y.Z>_linux_<arch>.tar.gz` par rôle (binaire `CGO_ENABLED=0`, `-trimpath`,
  version injectée par `-X main.version`, plus `LICENSE`, `README.md`, `CHANGELOG.md`, la
  configuration d'exemple et les unités systemd du rôle), archive reproductible (ordre,
  dates, propriétaires fixés, `gzip -n`) ; les paquets deb et rpm de l'agent serveur
  (`make packages`, version tirée de l'étiquette) ; `SHA256SUMS`. Le répertoire de sortie
  doit être vide.
- **Unité systemd du serveur** livrée (`deploy/systemd/ogsbom-server.service`) :
  `DynamicUser`, `StateDirectory=ogsbom` pour `vulndb.dir`, secrets dans un
  `EnvironmentFile` en `0600`, clé TLS par `LoadCredential`, durcissement aligné sur
  l'unité de l'agent dépôt.
- Pas de signature des binaires ni des paquets (T24, T26), pas d'image de conteneur
  (aucun lot ne la demande).

## Conséquences

- Publier = mettre à jour `CHANGELOG.md` sur `main`, puis `git tag -a vX.Y.Z` et le pousser.
- Les sommes SHA-256 protègent du téléchargement corrompu, pas d'un dépôt compromis :
  l'authenticité attend la signature (T24).
- Un échec du workflow après la création de l'étiquette se corrige par un commit sur `main`
  et une nouvelle étiquette (jamais en déplaçant une étiquette publiée).
