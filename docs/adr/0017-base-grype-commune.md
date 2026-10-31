# 0017 — Base Grype commune : archives en blocs dans PostgreSQL, cible, copie locale par instance

- Statut : Accepté
- Date : 2026-10-31
- Lot : T06

## Contexte

Le § 12 de l'architecture pose une base de vulnérabilités commune à toutes les instances :
une échéance `vulndb.check` (une seule instance) télécharge et vérifie l'archive, la range
dans `vulndb_archives` et fixe la cible dans `vulndb_state` ; chaque instance worker
synchronise sa copie locale, bascule atomiquement et exige la cible avant d'analyser. Il
restait à fixer comment stocker une archive de plusieurs centaines de Mio dans PostgreSQL,
qui télécharge (le métier ne dépend pas de `net/http`, § 4), comment valider une archive,
comment basculer sans interrompre les analyses en cours, et comment alerter.

Exploration : la base v6 fait 3,2 Gio décompressée, l'archive tar.zst environ 200 Mio ;
l'ouverture d'une base installée prend 2 à 5 s (somme xxh64 vérifiée) ; le client de
distribution de Grype télécharge en mode « répertoire » (go-getter décompresse l'archive
au vol), ce qui ne laisse pas d'archive à stocker.

## Décision

- **Stockage** : `vulndb_archives` (somme SHA-256 unique, taille, schéma, date de
  construction, origine `download` ou `import`) et `vulndb_archive_chunks` (blocs de
  8 Mio, `STORAGE EXTERNAL`). Écriture bloc par bloc dans une transaction, somme et
  taille revérifiées à la fin ; lecture d'un bloc par requête : la mémoire reste bornée à
  un bloc. `vulndb_state` est une ligne unique (cible, date, dernière vérification et son
  erreur).
- **Téléchargement hors du métier** : `vuln.Fetcher` (interface du métier) est implémenté
  par `internal/download` (`net/http`, mandataire de l'environnement, taille bornée par
  `vulndb.max_archive_mib`, contexte respecté), classé paquet serveur non métier dans
  `archtest`. `vuln/grype` n'utilise de Grype que la lecture de la liste
  (`latest.json`) et la résolution de l'adresse de l'archive, sans réseau.
- **Validation** : une archive n'est stockée et ne devient la cible qu'après (1) la
  vérification de sa SHA-256 contre la liste (téléchargement), (2) une installation
  complète par le curateur de Grype (décompression, hydratation, somme xxh64) et une
  ouverture réussie. L'installation validée reste dans `vulndb.dir` pour l'instance qui a
  vérifié. Une archive déjà stockée (même somme) redevient la cible sans téléchargement ;
  une liste plus ancienne que la cible est ignorée.
- **Changement de cible** : dans la transaction qui le fixe, job `analysis.rescan_all`
  (clé d'unicité, priorité basse).
- **Copie locale** (`vuln.Manager`) : un répertoire par archive (`<dir>/<id>`), installé
  depuis PostgreSQL dans un répertoire temporaire puis renommé (bascule atomique sur le
  disque) ; une archive dont un bloc est altéré n'est jamais installée ; une installation
  locale illisible est refaite. Une seule base ouverte, derrière un verrou
  lecture/écriture : une correspondance tient le verrou en lecture, la bascule prend le
  verrou en écriture, donc attend les correspondances en cours avant de fermer l'ancienne
  base et de supprimer son répertoire. Synchronisation au démarrage, puis toutes les
  `vulndb.sync_interval`, et avant chaque analyse (`Ensure`).
- **Disponibilité** : `/readyz` d'une instance worker échoue tant qu'aucune base n'est
  chargée ; une instance purement web n'en dépend pas.
- **Âge** : au-delà de `vulndb.max_age` (5 jours, décision du lot), callout sur chaque
  page d'administration de l'instance, métrique `lotor_vulndb_stale` et
  `lotor_vulndb_target_age_seconds` ; Grype ne refuse jamais une base pour son âge.
- **Hors ligne** : `vulndb.offline` désactive l'échéance ; `vuln.Checker.Import` range une
  archive fournie par l'exploitant avec les mêmes contrôles (sans somme annoncée) ; son
  écran arrive en T11.

## Conséquences

- PostgreSQL porte environ 200 Mio par archive conservée : la purge des anciennes archives
  (hors cible) reste à faire (T11, avec l'écran d'import).
- Chaque instance worker installe la base elle-même (environ 3,5 Gio, le double pendant
  une bascule) : à dimensionner et à documenter (`docs/operations.md`).
- Une installation de Grype ne prend pas de contexte : elle va à son terme même à
  l'arrêt ; le délai du job `vulndb.check` vaut deux fois `vulndb.download_timeout`.
- `vuln/grype` lit la fiche NVD d'un CVE par `VulnerabilityMetadata`, marquée dépréciée par
  Grype (qui l'emploie lui-même) : à surveiller aux montées de version.

## Alternatives écartées

- **Grand objet PostgreSQL (`lo_*`)** : API à part, droits et nettoyage spécifiques
  (`vacuumlo`) pour un gain nul face à des blocs `bytea`.
- **Une seule valeur `bytea`** : 200 Mio lus d'un bloc en mémoire à chaque synchronisation.
- **Client de distribution de Grype** : décompresse l'archive au téléchargement (aucune
  archive à stocker) et ne prend pas de contexte.
- **Exception à la règle « pas de `net/http` dans le métier » pour `vuln/grype`** : une
  interface injectée garde la règle et rend le téléchargement testable par un faux.
- **Chaque instance télécharge sur Internet** : des instances à des versions différentes
  produiraient des constats contradictoires, et un site isolé ne pourrait rien.
