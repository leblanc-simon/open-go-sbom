# 0007 — Bibliothèques d'Anchore derrière des adaptateurs

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

Syft et Grype sont des bibliothèques à l'API mouvante (versions 1.x et 0.x), au graphe de
dépendances très large. Explorations menées avec Syft v1.55.0 et Grype v0.121.0
(programmes jetables, non conservés) :

- **CycloneDX 1.7** : Syft encode et décode CycloneDX JSON 1.7 (sa version par défaut) ;
  un SBOM d'hôte Ubuntu 24.04 de 837 paquets a été produit en CycloneDX 1.7, SPDX 2.3 et
  Syft JSON, puis redécodé sans perte de distribution.
- **Grype en bibliothèque** : `grype.LoadVulnerabilityDB` charge une base v6 depuis un
  répertoire (`installation.Config.DBRootDir`) ; `pkg.ProvideFromReader` transforme le
  SBOM brut en paquets et contexte de distribution ; `grype.VulnerabilityMatcher` avec
  `matcher.NewDefaultMatchers` produit les correspondances. Les trois formats donnent
  exactement les mêmes 7 206 correspondances. Chaque correspondance porte le purl du
  paquet d'origine (`Match.Package.PURL`, qualificatifs `distro`, `arch`, `upstream`
  conservés), EPSS et KEV (`Vulnerability.Metadata.EPSS`, `.KnownExploited`) et le score
  `Metadata.RiskScore()` : log4j-core 2.14.1 donne deux correspondances KEV de risque
  99 et 100. Les identifiants sont ceux de la source (GHSA pour l'écosystème Java) ;
  `NormalizeByCVE` permet de les ramener aux CVE.
- **Base Grype** : schéma v6.1.10, archive téléchargée puis décompressée en 3,2 Gio
  (`vulnerability.db`), chargement initial 3 min 12 s (téléchargement compris), puis
  2 s ; correspondance de 837 paquets en 16 s sur 4 cœurs.
- **Client Docker** : le graphe de stereoscope v0.3.4 contient déjà
  `github.com/moby/moby/client` (v0.6.0) et `github.com/containerd/containerd/v2/client`.
- **SQLite** : Syft refuse de cataloguer les bases RPM récentes (RHEL 9 et plus) si aucun
  pilote `database/sql` « sqlite » n'est enregistré ; `modernc.org/sqlite` (pur Go, déjà
  dans le graphe d'open-go-base) convient.
- **Taille** d'un binaire qui importe Syft (`CGO_ENABLED=0`, `-trimpath -s -w`) :
  82 Mo en amd64, 77 Mo en arm64 (116 Mo sans `-s -w`).

## Décision

- Imports directs autorisés : `github.com/anchore/syft/...` dans `sbom/syft`,
  `vuln/grype`, `hostagent`, `repoagent` ; `github.com/anchore/grype/...` dans
  `vuln/grype`, `version/grypeversion` ; `github.com/anchore/grant/...` dans
  `license/grant`. Vérifié par `internal/archtest` en CI.
- Les types d'Anchore ne traversent jamais la frontière d'un adaptateur.
- Grype reçoit le SBOM brut (`pkg.ProvideFromReader`), jamais une reconstruction.
- Les binaires qui cataloguent avec Syft importent `modernc.org/sqlite` pour les bases RPM.
- L'agent serveur utilise le client Docker déjà présent dans le graphe de stereoscope
  (T13), sans dépendance nouvelle.

## Conséquences

- Une montée de version d'Anchore ne touche que les adaptateurs et leurs tests.
- La base Grype occupe environ 3,5 Gio par instance worker : à documenter dans
  `docs/operations.md` (T06) avec l'espace disque nécessaire pendant une bascule (deux
  copies).
- Un agent de 80 Mo est acceptable pour un binaire statique ; la mesure est refaite à
  chaque lot qui ajoute du code aux agents.

## Alternatives écartées

- Appeler les binaires `syft` et `grype` : dépendance d'exploitation, sortie à analyser,
  versions non maîtrisées.
- Convertir le SBOM dans un format maison avant Grype : perte d'information (distribution,
  paquets sources, CPE) et faux négatifs.
