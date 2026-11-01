# Journal des modifications

Toutes les évolutions notables de lotor. Format :
[Keep a Changelog 1.1.0](https://keepachangelog.com/fr/1.1.0/) ; versions selon
[SemVer](https://semver.org/lang/fr/). Avant la v1.0, toute version est une préversion et
peut changer la configuration ou l'API ; les migrations de base restent toujours
appliquées automatiquement, sans retour arrière.

## [Non publié]

### Ajouté

- Équipes et droits (T16, ADR 0034) : chaque projet appartient à une équipe ; un membre ne
  voit que les projets de ses équipes, sur toutes les surfaces (listes, fiches, recherche
  et exports, API utilisateur, tableau de bord, vulnérabilités, composants, agents), et y
  agit selon son rôle d'équipe (lecteur, analyste, administrateur d'équipe) ; écrans des
  équipes et de leurs membres, rattachement d'un projet à une autre équipe, agents et
  jetons d'inscription rattachés à une équipe ; matrice des droits
  [`docs/security/permissions.md`](docs/security/permissions.md), générée depuis le code.
- Invitations : un administrateur d'organisation invite une adresse, le compte accepte ou
  décline depuis « Mon compte » → « Invitations ».
- Conteneurs en projets enfants (T13, ADR 0040 et 0041) : l'agent serveur inventorie les
  conteneurs Docker et Podman en cours d'exécution (option `containers.enabled`,
  **désactivée par défaut** : l'accès à la socket d'un moteur équivaut à root) ; chaque
  service Compose, ou chaque conteneur hors Compose, devient un projet enfant du serveur,
  dans son équipe, avec son SBOM ; une image partagée n'est analysée qu'une fois. Fiche du
  serveur avec ses conteneurs et leurs constats par périmètre ; filtre « Inclure les
  conteneurs » des listes de projets et de la recherche (écran et API, `containers=1`) ;
  un conteneur absent depuis `containers.archive_after` (7 jours) est archivé et revient
  s'il redémarre. Nouvelle opération de l'API des agents `reportContainers`.

### Modifié

- Le rôle d'organisation vaut désormais « membre » ou « administrateur » (les rôles
  `viewer` et `analyst` disparaissent). La migration 016 crée une équipe « Général » par
  organisation, y rattache projets, jetons d'inscription et agents serveur, et y fait
  entrer chaque membre avec son ancien rôle : aucun accès n'est perdu.
- Le scan de l'hôte par l'agent serveur se fait hors ligne, comme celui des images : Syft
  n'exécute plus `go list` sur les modules Go trouvés sous `/` et ne cherche plus de
  licences sur le réseau. L'inventaire d'un hôte qui porte des modules Go peut changer une
  fois (renvoi de son SBOM).

### Sécurité

- SEC-09 corrigé : l'ajout d'un membre passe par une invitation à accepter, avec une
  réponse identique que le compte existe ou non.

## [0.1.0] - 2026-11-01

Préversion du **lot 1 · MVP inventaire** : un parc de serveurs et de dépôts inventorié,
analysé chaque jour avec Grype et interrogé. Binaires des trois rôles (linux amd64 et
arm64), paquets deb et rpm de l'agent serveur, sommes SHA-256. Installation :
[`docs/operations.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/operations.md) ; premiers pas :
[`docs/demarrage.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/demarrage.md) ([English](https://github.com/leblanc-simon/lotor/blob/main/docs/getting-started.md)).

### Ajouté

#### Fondations (T00, T01, T02)

- Dépôt, outillage qualité et CI identique à `make ci` : formatage, code généré, `go vet`
  et staticcheck sur toutes les étiquettes de test, tests unitaires avec `-race`, tests
  d'intégration PostgreSQL, govulncheck, construction amd64 et arm64, autoanalyse des
  binaires par Syft et Grype ([#1](https://github.com/leblanc-simon/lotor/pull/1),
  [#2](https://github.com/leblanc-simon/lotor/pull/2)).
- Serveur `lotor-server` sur open-go-base : configuration YAML et `LOTOR_*`, migrations
  sous verrou et immuables (somme SHA-256), deux rôles PostgreSQL (propriétaire et
  exécution, refus d'un rôle qui contournerait la RLS), TLS natif ou mandataire inverse,
  en-têtes de sécurité et CSP stricte, sondes `/healthz` et `/readyz`, métriques
  Prometheus, interface traduite en français et en anglais, thèmes clair et sombre
  ([#3](https://github.com/leblanc-simon/lotor/pull/3)).
- File de traitements PostgreSQL : baux renouvelés, réessais exponentiels, priorités,
  plafond par organisation, échéances uniques sur un parc d'instances, arrêt propre
  ([#4](https://github.com/leblanc-simon/lotor/pull/4)).

#### Comptes, organisations et agents (T03, T04)

- Comptes locaux avec TOTP obligatoire, premier administrateur par variables de démarrage,
  procédure de secours tracée, administration des comptes ; organisations isolées par la
  sécurité au niveau des lignes de PostgreSQL (RLS forcée), rôles lecteur, analyste,
  administrateur ; journal d'audit ([#5](https://github.com/leblanc-simon/lotor/pull/5)).
- Projets (dépôts et serveurs), agents, jetons d'agent et jetons d'inscription, API des
  agents générée depuis `api/openapi.yaml`, limitation de débit par jeton
  ([#6](https://github.com/leblanc-simon/lotor/pull/6)).

#### Inventaire et analyse (T05, T06)

- Ingestion des SBOM CycloneDX JSON 1.5 à 1.7, SPDX JSON 2.3 et Syft JSON : bornes de
  taille, de profondeur et de composants, décodage dans un worker, inventaire normalisé
  (purl canoniques), instantanés par référence, téléchargement du SBOM reçu ou réencodé
  en CycloneDX 1.6 ou SPDX 2.3 ([#7](https://github.com/leblanc-simon/lotor/pull/7)).
- Analyse de vulnérabilités par Grype : base v6 commune à toutes les instances, rangée par
  blocs dans PostgreSQL, vérifiée et synchronisée sans interruption ; réanalyse de tout
  le parc à chaque nouvelle base ; constats avec sévérité, CVSS, EPSS, KEV et versions
  corrigées ; onglet « Constats », fiches vulnérabilité et composant
  ([#9](https://github.com/leblanc-simon/lotor/pull/9)).

#### Agents (T07, T08)

- Agent serveur `lotor-host-agent` (Linux amd64 et arm64) : inscription par jeton,
  inventaire Syft de l'hôte (paquets du système et des langages), envoi seulement quand
  l'inventaire change, scan à la demande, mTLS, démon ou timer systemd sans root
  (`CAP_DAC_READ_SEARCH`), paquets deb et rpm
  ([#10](https://github.com/leblanc-simon/lotor/pull/10)).
- Agent dépôt `lotor-repo-agent` : GitHub App et compte de service GitLab, webhooks
  signés, rattrapage des commits manqués, clonage du seul commit visé dans un
  environnement git maîtrisé, analyse Syft sans exécuter de code du dépôt, SBOM
  déterministe ([#8](https://github.com/leblanc-simon/lotor/pull/8)).

#### Exploitation des données (T09, T10)

- Tableau de bord d'organisation et en-tête de projet : constats ouverts par sévérité,
  KEV, tendance sur 30, 90 ou 365 jours, délai médian de correction, agents muets,
  projets et composants les plus exposés
  ([#11](https://github.com/leblanc-simon/lotor/pull/11)).
- Recherche transverse par nom, purl, plage de versions `vers`, vulnérabilité (CVE ou
  GHSA) et empreinte, filtres, export CSV et JSON ; API utilisateur en lecture avec jetons
  d'accès personnels ([#12](https://github.com/leblanc-simon/lotor/pull/12)).

#### Recette du lot 1 (T11)

- Administration de l'instance : traitements en échec (relancer, abandonner), état de la
  base de vulnérabilités par instance, import manuel d'une archive pour les sites isolés,
  purge des archives ([#13](https://github.com/leblanc-simon/lotor/pull/13)).
- Page de confirmation des actions irréversibles, plan du site, titres de page distincts
  ([#14](https://github.com/leblanc-simon/lotor/pull/14)).
- Unité systemd du serveur, workflow de publication et cible `make release`, guide
  d'exploitation complété (installation, sauvegarde et restauration, mise à jour,
  supervision), guides de démarrage en français et en anglais
  ([#16](https://github.com/leblanc-simon/lotor/pull/16)).

### Sécurité

- Revue de sécurité du lot 1 (OWASP Risk Rating, aucune faiblesse haute ni critique) et
  corrections : verrouillage par compte des codes TOTP, révocation des jetons personnels
  à toute réinitialisation, mot de passe temporaire imposé après réinitialisation du TOTP,
  durée absolue de session, jeton CSRF lié à la session et protection inter-origines,
  cookies `__Host-`, journaux d'audit en ajout seul, quotas d'ingestion, périmètre
  obligatoire de l'agent dépôt ([#15](https://github.com/leblanc-simon/lotor/pull/15)).

### Accessibilité

- Audit RGAA de tous les écrans du lot 1 : 100 % des critères applicables conformes après
  corrections ([grille](https://github.com/leblanc-simon/lotor/blob/main/docs/accessibilite/grille-rgaa-lot1.md),
  [#14](https://github.com/leblanc-simon/lotor/pull/14)).

[Non publié]: https://github.com/leblanc-simon/lotor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/leblanc-simon/lotor/releases/tag/v0.1.0
