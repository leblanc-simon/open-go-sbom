# Avancement

Journal de bord de la réalisation autonome des lots. Chaque entrée renvoie au Journal de la
fiche, qui fait foi pour le détail des décisions. Les décisions prises sans validation
explicite de l'utilisateur sont marquées **[à relire]**.

## Lot 2

Réalisation autonome du lot 2 (T16, puis T12, T13, T14, T17, T15 et la recette T18),
demandée le 1er novembre 2026 : enchaîner jusqu'à la recette sans attendre les réponses de
l'utilisateur, en consignant chaque décision pour une relecture a posteriori.

| Lot | PR | Statut | Décisions à relire |
| --- | --- | --- | --- |
| T16 | #21 | Terminé (PR à fusionner) | Filtre d'équipe déclaré à la transaction, fermé par défaut ; matrice des droits (administrateur d'équipe sans gestion des équipes ni des membres de l'organisation, rattachement avec droit dans les deux équipes) ; 404 pour une équipe invisible ; agents sans équipe = agents d'organisation, agents dépôt existants d'organisation ; équipe « Général » aussi pour une nouvelle organisation, « General » en anglais ; invitations de 30 jours, sans équipe, bornées, nouvelle fonction `crossorg` ; tendance d'un membre additionnée par projet ; point d'essai `routeStub` — tous **[à relire]** |
| T13 | à venir | Terminé (PR à fusionner) | Client HTTP sur socket Unix plutôt que le client moby (écart au § 5) ; scan de l'image exportée (`docker save`) ; catalogueurs hors ligne aussi pour l'hôte ; équipe imposée par clé étrangère en cascade ; signalement dédié qui vaut signal de vie ; archivage à la main qui tient ; conteneurs écartés des listes et de la recherche, comptés au tableau de bord ; agrégat par vulnérabilités distinctes — tous **[à relire]** |

### Décisions à relire, par thème

#### Équipes, droits et isolement

- Filtre d'équipe par réglage de transaction (`db.Visible`, `lotor.teams`) et fonction
  `lotor_team_visible`, qui échoue sans déclaration ; politiques RLS par équipe écartées
  ([ADR 0034](../docs/adr/0034-equipes-et-droits.md), [T16](lots/T16-equipes-droits.md#décisions)).
- Matrice des droits ([`permissions.md`](../docs/security/permissions.md)) : rôles
  minimaux de chaque permission, liste des membres visible de tout membre,
  `finding.triage` déclaré pour T14 ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- 404 pour une ressource d'une équipe invisible, 403 pour un droit manquant
  ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- Agents : équipe facultative, agents dépôt existants d'organisation, agents serveur dans
  « Général » ; équipe supprimée : agents rendus à l'organisation, jetons d'inscription
  supprimés ; rattachement d'un dépôt qui perd un agent d'équipe, d'un serveur qui emmène
  le sien ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- Équipe « Général » créée aussi avec chaque nouvelle organisation ; « General » pour une
  organisation en anglais ([T16](lots/T16-equipes-droits.md#décisions)).
- Tableau de bord d'un membre : tendance additionnée par projet ; fiche composant en 404
  hors des équipes visibles ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- Point d'essai `routeStub` pour le test des droits dérivé de la matrice
  ([T16](lots/T16-equipes-droits.md#décisions)).

#### Sécurité et identité

- SEC-09 corrigé par des invitations : 30 jours, 200 en attente par organisation, une par
  adresse, sans équipe, adresse déjà membre non invitée ; ajout direct gardé pour
  l'administration de l'instance ; nouvelle fonction `crossorg`
  `lotor_user_invitations` ([ADR 0034](../docs/adr/0034-equipes-et-droits.md),
  [modèle de menace](../docs/security/threat-model.md)).

#### Conteneurs (T13)

- API Docker de Docker et Podman par un client HTTP sur socket Unix, sans bibliothèque
  cliente, plutôt que le client moby du graphe de stereoscope (écart au § 5 de
  l'architecture, mis à jour) ; moteur détecté par `/version`
  ([ADR 0041](../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- Image exportée (`docker save`) dans `<state_dir>/images` et scannée par la source
  `docker-archive` de Syft, une fois par image, 4 096 Mio au plus ; empreintes d'images
  gardées par l'agent et confirmées par le serveur, jamais de SBOM sur le disque
  ([ADR 0041](../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- Catalogueurs de Syft hors ligne pour le scan de l'hôte aussi (plus de `go list` sous
  `/`) : un hôte qui porte des modules Go renvoie une fois son SBOM
  ([ADR 0041](../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- Équipe du conteneur imposée par une clé étrangère `ON UPDATE CASCADE` vers l'hôte ;
  conteneur sans agent propre ; nom `hôte/identité`
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Signalement `POST /api/v1/agent/containers` (500 identités, 1 Mio), qui vaut signal de
  vie et porte les comptes rendus d'inventaire ; l'hôte vient du jeton
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Conteneur archivé à la main : reste archivé, l'agent l'ignore ; archivé pour absence :
  revient seul, pas de réactivation à la main
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Conteneurs écartés par défaut des listes et de la recherche (`containers=1` s'ajoute à
  `type`), comptés dans le tableau de bord de l'organisation
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Fiche hôte : vulnérabilités distinctes par projet à la plus haute sévérité, conteneurs
  archivés hors du total ; état « absent » d'un conteneur non signalé depuis le dernier
  inventaire de l'hôte, à une heure près
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).

#### Écarts

- T16 : captures d'écran clair et sombre non faites (aucune CSS nouvelle ; audit RGAA du
  lot 2 en T18) ; filtre « équipe » de la recherche non livré (recherche filtrée par les
  équipes visibles) ([T16](lots/T16-equipes-droits.md#écarts)).
- T13 : captures clair et sombre non faites (composants existants, un seul modificateur
  CSS) ; Podman non essayé (Docker 29 essayé pour de vrai) ; purge des conteneurs archivés
  depuis longtemps renvoyée à T18 ([T13](lots/T13-conteneurs.md#écarts)).

### Actions pour l'utilisateur

1. Relire les décisions **[à relire]** ci-dessus (ADR 0034, 0040, 0041, matrice
   [`docs/security/permissions.md`](../docs/security/permissions.md)).
2. Après la publication d'une version contenant T13 : essayer l'inventaire des conteneurs
   sur un hôte réel (Docker avec docker compose, puis Podman sans root avec son ACL,
   `docs/operations.md`, « Conteneurs »), en connaissance de l'équivalence root de la
   socket.
3. Après la publication d'une version contenant T16 : vérifier sur une instance réelle
   que la migration 016 a placé chaque membre dans l'équipe « Général » avec son ancien
   rôle (page **Équipes** de chaque organisation).

## Lot 1

Journal de bord de la réalisation autonome du lot 1 (T00 à T11), demandée le
31 octobre 2026. Chaque entrée renvoie au Journal de la fiche, qui fait foi pour le détail
des décisions. Les décisions prises sans validation explicite de l'utilisateur sont
marquées **[à relire]**.

### Synthèse

Le lot 1 est **réalisé** : le critère du cahier des charges, « un parc pilote inventorié
et interrogé », est passé (recette de T11) sur trois serveurs (Debian 12, Rocky Linux 9,
Alpine 3.18) et quatre dépôts publics réels (deux de GitHub, deux de GitLab, servis par une
forge simulée) : chaque projet a un instantané de moins de 24 h analysé avec la vraie base
Grype, et la recherche (écran et API) renvoie exactement les listes de projets établies à
la main pour les trois CVE de contrôle. Toutes les cibles chiffrées sont tenues sur une
machine moins puissante que la référence. Restent à l'utilisateur : la relecture des
décisions ci-dessous, l'étiquette `v0.1.0` et l'essai de l'agent dépôt sur une vraie
forge (voir « Actions pour l'utilisateur »).

| Lot | PR | Statut | Décisions à relire |
| --- | --- | --- | --- |
| T00 | #1, #2 | Terminé | `modernc.org/sqlite` ajouté au § 5 **[à relire]** ; OpenAPI 3.1 ; SQL à la main |
| T01 | #3 | Terminé | Migrations et rôles (ADR 0010) ; fragments de config au fil des lots, fragment `HTTP` ; `Seal`/`Open` avec données associées ; en-têtes de sécurité (`base-uri`, HSTS sans sous-domaines) ; thème `light-dark()` + cookie ; polices droites seulement ; pied de page hors planche — tous **[à relire]** |
| T02 | #4 | Terminé | Conception de la file (ADR 0011 : horloge Go, `synchronous_commit = off` pour les transitions d'état, plafond strict, libération sans tentative comptée…) ; valeurs par défaut des workers ; correction de `PoolConfig.MaxIdleConns` (T01) — **[à relire]** |
| T03 | #5 | Terminé | Propriétaire `BYPASSRLS` pour `crossorg` (ADR 0012) ; secrets TOTP chiffrés, `secrets.keys` obligatoire (ADR 0013) ; secours par ticket (deux variables) ; TOTP avant changement de mot de passe ; 404 pour l'administration, 403 dans l'organisation ; `jobs.org_id` sans clé étrangère ; open-go-base en pseudo-version, étiquette `v1.1.0` à pousser — tous **[à relire]** |
| T04 | #6 | Terminé | Format des jetons et deux fonctions `crossorg` pour l'organisation d'un jeton (ADR 0014) ; `ratelimit.WithKeyFunc` dans open-go-base (étiquette `v1.2.0` à pousser) et suppression d'`internal/ratelimit` ; refus de jetons limités par IP ; hôte déjà suivi refusé à l'inscription ; jeton d'agent d'inscription sans expiration ; « muet » sur le dernier contact ; écriture réservée aux administrateurs ; valeurs par défaut — tous **[à relire]** |
| T05 | #7 | Terminé | Décodage dans le worker, sous-processus écarté (ADR 0015) ; règles de l'inventaire (ADR 0016 : purl de packageurl-go, identification faible par élément, CPE hors empreinte, commit renvoyé = ensemble remplacé, courant = date de scan, refus stockés en `failed`, doublon de dépôt en 200) ; validation sans l'énumération des licences SPDX de CycloneDX à la réception ; bornes par défaut (32/64 Mio, profondeur 64, 50 000 composants, 5 min, 2 par organisation) ; directive `go` 1.26.8 (Syft) — tous **[à relire]** |
| T06 | #9 | Terminé | Base Grype commune en blocs dans PostgreSQL, téléchargement par `internal/download` (ADR 0017) ; correspondance hors transaction et écriture sous verrou, identifiants CVE, réanalyse par organisation sans nouvelle fonction `crossorg` (ADR 0018) ; jeu synthétique et autoanalyse par `go run` des commandes Syft et Grype (ADR 0019) ; valeurs par défaut `vulndb.*` ; mesures faites sur 4 cœurs, pas sur la machine de référence — tous **[à relire]** |
| T07 | #10 | Terminé | Envoi conditionnel confirmé par le serveur, Syft JSON, demande de scan remise une fois, muet sur le dernier inventaire pour un agent serveur (ADR 0020) ; unités, secrets, mTLS par middleware, paquets nfpm (ADR 0021) ; scan à la demande ouvert aux analystes ; valeurs par défaut ; cibles 5 min de CPU et 1 Gio par scan ; agent dépôt branché sur le client commun (adresse https exigée) — tous **[à relire]** |
| T08 | #8 | Terminé | Agent dépôt (ADR 0023) : webhook = signal, tête résolue auprès de la forge ; `git fetch --depth 1` du commit au lieu de `clone --single-branch` ; SBOM déterministe (ni numéro de série ni horodatage) ; Syft sans `go list` ni réseau ; échecs définitifs non retentés avant redémarrage ; secrets par `credential:<nom>` ou fichier 0600 ; jeton GitHub restreint à `contents: read` ; valeurs par défaut ; droits GitLab vérifiables seulement sur forge réelle — tous **[à relire]** |
| T09 | #12 | Terminé | Recherche (ADR 0024) : deux nouvelles fonctions `crossorg` de recherche par nom et empreinte (organisation lue dans `lotor.org_id`, contournent la RLS pour les index GIN), sous-chaîne puis trigrammes, bornes, export en flux borné en nombre et durée ; jetons personnels en table globale valables sur les organisations du compte, expiration obligatoire, sans session dans l'API (ADR 0025) ; comparateurs de Grype corrigés et plages vers maison (ADR 0026) ; défauts `user_api` ; écarts à la maquette ; mesures sur 4 cœurs — tous **[à relire]** |
| T10 | #11 | Terminé | Tableau de bord (ADR 0027) : constats des références actives des projets actifs ; statistiques réécrites toutes les heures sous la date du jour ; `project_daily_stats` en plus d'`org_daily_stats` ; pas de nouvelle fonction `crossorg` ; seuil « muet » de 7 jours pour toute l'interface ; périodes 30/90/365 j ; tuiles sans lien (pas de liste transverse avant T09) ; section « Alertes » et objectifs de délai renvoyés à T15 ; mesures sur 4 cœurs partagés — tous **[à relire]** |
| T11 (1/2, administration) | #13 | Terminé | Administration de l'instance (ADR 0028) : archive téléversée rangée dans PostgreSQL puis installée par un job, jeton CSRF en tête du formulaire présenté à csrfx, archive importée cible même plus ancienne, un import à la fois, état par instance (`vulndb_instances`), purge de toutes les archives non cibles avec confirmation ; `download_timeout` borne aussi le téléversement ; test instable corrigé dans le test (bail simulé complet) ; codes de secours de mfax absents d'open-go-base, reportés à T18 — tous **[à relire]** |
| T11 (accessibilité) | #14 | Terminé | Audit RGAA : 13 NC corrigées, 100 % des critères applicables ; page de confirmation commune pour les actions irréversibles (abandon d'un traitement compris) ; plan du site plutôt que la recherche pour 12.1 ; préfixe « Erreur : » sur tout écran en 4xx ; abréviations des sévérités — tous **[à relire]** |
| T11 (sécurité) | #15 | Terminé | Revue de sécurité du lot 1 (14 constats, 0 haut ni critique) : 3 Medium, 6 Low et 2 Note corrigés (SEC-11 et SEC-14 en partie), SEC-13 accepté, SEC-09 (Low) accepté jusqu'à T16 ; open-go-base v1.3.0 (PR #3 fusionnée, étiquette à pousser) ; ADR 0029 à 0031 — tous **[à relire]** |
| T11 (recette) | #16 | Terminé (v0.1.0 à publier par l'utilisateur) | Parc pilote en conteneurs et forge simulée ; CVE de contrôle ; cibles tenues sur 4 cœurs, valant pour la référence ; publication des versions (ADR 0032) et unité systemd du serveur ; guides de démarrage FR et EN séparés de `utilisation.md` ; outillage de recette hors dépôt — tous **[à relire]** |
| Renommage en lotor | — | Terminé | Correspondance unique `open-go-sbom`/`ogsbom` → `lotor` partout, migrations réécrites en place avant toute publication, identité visuelle dans `docs/logo/` et l'interface (ADR 0033) — **[à relire]** |

### Décisions à relire, par thème

Chaque point renvoie à l'ADR ou au Journal qui le détaille.

#### Architecture, base de données et file

- Migrations sous verrou, immuables, deux rôles PostgreSQL ([ADR 0010](../docs/adr/0010-migrations-et-roles-postgresql.md), [T01](lots/T01-socle-serveur.md)).
- Conception de la file : horloge Go, `synchronous_commit = off` pour les transitions, plafond strict par organisation, libération sans tentative comptée, défauts des workers ([ADR 0011](../docs/adr/0011-conception-de-la-file.md), [T02](lots/T02-file-de-traitements.md)).
- Isolement : propriétaire `BYPASSRLS` pour `crossorg`, `jobs.org_id` sans clé étrangère ([ADR 0012](../docs/adr/0012-isolement-des-organisations.md), [T03](lots/T03-comptes-organisations.md)) ; fonctions `crossorg` des jetons ([ADR 0014](../docs/adr/0014-jetons-et-api-des-agents.md)) et de la recherche ([ADR 0024](../docs/adr/0024-recherche-transverse.md)).
- Journal d'audit en ajout seul, rôle d'exécution sans `CREATE`, quotas d'ingestion (200 envois par référence et par jour, 10 Gio par organisation), plafonds par compte ([ADR 0030](../docs/adr/0030-durcissement-base-et-quotas.md)).

#### Sécurité et identité

- Secrets TOTP chiffrés, `secrets.keys` obligatoire, secours par ticket ([ADR 0013](../docs/adr/0013-comptes-et-second-facteur.md), [T03](lots/T03-comptes-organisations.md)).
- Verrouillage par compte des codes TOTP (10 en 15 min, 15 min doublées jusqu'à 24 h), révocation d'office des jetons, réinitialisation du TOTP avec mot de passe temporaire, `bootstrap.rescue_password`, durée absolue de session de 7 jours ([ADR 0029](../docs/adr/0029-remediation-des-identifiants.md)).
- CSRF lié à la session, `http.CrossOriginProtection`, cookies `__Host-` avec `cookie_secure: on` ([ADR 0031](../docs/adr/0031-csrf-cookies-et-perimetre-de-l-agent-depot.md)).
- Constats acceptés : SEC-09 (énumération des comptes par un administrateur d'organisation, jusqu'à T16) et SEC-13 ([revue de sécurité](lots/T11-recette-lot-1.md#revue-de-sécurité)).
- En-têtes de sécurité (`base-uri`, HSTS sans sous-domaines), `Seal`/`Open` avec données associées ([T01](lots/T01-socle-serveur.md)) ; 404 pour l'administration, 403 dans l'organisation ([T03](lots/T03-comptes-organisations.md)).
- Codes de secours de mfax reportés à T18 ([T11, partie 1](lots/T11-recette-lot-1.md#partie-1--administration-de-linstance-et-corrections)).

#### Ingestion et inventaire

- Décodage dans le worker ([ADR 0015](../docs/adr/0015-decodage-des-sbom-dans-le-worker.md)) ; règles de l'inventaire ([ADR 0016](../docs/adr/0016-ingestion-et-inventaire.md)) ; validation sans l'énumération des licences SPDX, bornes par défaut ([T05](lots/T05-ingestion.md)).

#### Analyse de vulnérabilités

- Base Grype commune en blocs dans PostgreSQL ([ADR 0017](../docs/adr/0017-base-grype-commune.md)) ; correspondance et constats, identifiants CVE ([ADR 0018](../docs/adr/0018-analyse-et-constats.md)) ; import d'archive, cible même plus ancienne, purge ([ADR 0028](../docs/adr/0028-administration-de-la-base-et-des-traitements.md)) ; défauts `vulndb.*` ([T06](lots/T06-analyse-vulnerabilites.md)).

#### Agents

- Agent serveur : envoi conditionnel, Syft JSON, « muet » sur le dernier inventaire ([ADR 0020](../docs/adr/0020-agent-serveur-envoi-conditionnel.md)) ; unités, mTLS par middleware, paquets nfpm ([ADR 0021](../docs/adr/0021-deploiement-agent-serveur.md)) ; cibles 5 min de CPU et 1 Gio par scan ([T07](lots/T07-agent-serveur.md)).
- Jetons et API des agents, jeton d'agent sans expiration, hôte déjà suivi refusé ([ADR 0014](../docs/adr/0014-jetons-et-api-des-agents.md), [T04](lots/T04-projets-agents.md)).
- Agent dépôt : webhook = signal, `git fetch --depth 1` du commit, SBOM déterministe, Syft sans `go list` ni réseau, jeton GitHub restreint ([ADR 0023](../docs/adr/0023-agent-depot.md)) ; `allowed_namespaces` obligatoire ([ADR 0031](../docs/adr/0031-csrf-cookies-et-perimetre-de-l-agent-depot.md)).

#### Recherche et tableau de bord

- Recherche : sous-chaîne puis trigrammes, bornes, export en flux ([ADR 0024](../docs/adr/0024-recherche-transverse.md)) ; jetons personnels ([ADR 0025](../docs/adr/0025-jetons-d-acces-personnels.md)) ; comparaison de versions et plages `vers` ([ADR 0026](../docs/adr/0026-comparaison-de-versions.md)).
- Tableau de bord : statistiques horaires sous la date du jour, seuil « muet » de 7 jours, périodes, renvois à T15 ([ADR 0027](../docs/adr/0027-tableau-de-bord.md)).

#### Interface et accessibilité

- Thème `light-dark()` et cookie, polices droites, pied de page ([T01](lots/T01-socle-serveur.md)) ; écarts à la maquette ([T09](lots/T09-recherche.md)).
- Page de confirmation commune, plan du site, préfixe « Erreur : », abréviations des sévérités ([audit RGAA](lots/T11-recette-lot-1.md#audit-rgaa)).

#### Exploitation, mesures et publication

- Cibles chiffrées tenues sur 4 cœurs (machine moins puissante que la référence), cibles du cahier des charges encore « proposées » à confirmer ([mesures de T11](lots/T11-recette-lot-1.md#mesures-consolidées), [`benchmarks.md`](../docs/benchmarks.md)).
- Publication des versions : étiquette sur `main`, préversions seulement, archives et paquets, unité systemd du serveur ([ADR 0032](../docs/adr/0032-publication-des-versions.md)).
- Recette : parc pilote en conteneurs, forge simulée, outillage gardé hors dépôt ([recette de T11](lots/T11-recette-lot-1.md#recette)).

#### Dépendances et open-go-base

- `modernc.org/sqlite` ([T00](lots/T00-fondations.md)) ; directive `go` 1.26.8 imposée par Syft ([T05](lots/T05-ingestion.md)).
- Évolutions d'open-go-base `v1.1.0` (T03), `v1.2.0` (`ratelimit.WithKeyFunc`, T04), `v1.3.0` (verrouillage de mfax, `csrfx.WithSessionBinding`, T11), utilisées par l'étiquette `v1.3.0`.

### Actions pour l'utilisateur

Le mandataire git de la session refuse les pushs d'étiquettes (HTTP 403) : `v0.1.0`
n'est pas posée. À faire, dans l'ordre (les étapes 1 à 3 sont faites) :

1. **Fait.** Renommer le dépôt GitHub `leblanc-simon/open-go-sbom` en `leblanc-simon/lotor`
   (*Settings* → *General* → *Repository name*), puis `git remote set-url origin
   https://github.com/leblanc-simon/lotor.git` dans le clone local (et renommer le
   dossier si souhaité). Si `leblanc.io` sert des métadonnées `go-import`, ajouter celle de
   `leblanc.io/lotor` ([ADR 0033](../docs/adr/0033-renommage-en-lotor.md)).
2. **Fait.** Pousser les étiquettes annotées d'open-go-base créées localement :
   `git -C ../open-go-base push origin v1.1.0` (commit `b9ccc67`, T03),
   `git -C ../open-go-base push origin v1.2.0` (commit `3534c14`, `ratelimit.WithKeyFunc`),
   `git -C ../open-go-base push origin v1.3.0` (commit `9a7b91f`, PR #3 : verrouillage par
   compte de mfax, `Confirm`, `WithChallengeCookieName`, `csrfx.WithSessionBinding`).
   Toutes compatibles.
3. **Fait.** Dans lotor, sur une branche : `go get leblanc.io/open-go-base@v1.3.0 && go mod
   tidy` (même code que la pseudo-version actuelle `v1.0.2-0.20261031121913-9a7b91fdbbfe` ;
   ne pas utiliser `v1.1.0` ni `v1.2.0`), `make ci`, PR, fusion quand la CI est verte.
4. Relire les décisions **[à relire]** ci-dessus, et confirmer (ou corriger) au cahier des
   charges les cibles de performance encore « proposées » (§ objectifs et § volumétrie ;
   mesures : Journal de T11). Une cible changée se reporte dans `docs/benchmarks.md`.
5. Essayer l'agent dépôt sur une vraie GitHub App et un vrai projet GitLab : procédure pas
   à pas dans [`docs/operations.md`](../docs/operations.md#recette-sur-une-vraie-forge)
   (une demi-heure). La recette n'a pu l'exercer que contre une forge simulée.
6. Publier la préversion **v0.1.0**, une fois les étapes 1 à 3 sur `main` :
   1. vérifier que la section `## [0.1.0] - 2026-11-01` de `CHANGELOG.md` est à jour (date
      du jour de la pose, ajouts éventuels) et que la CI de `main` est verte ;
   2. `git fetch origin && git tag -a v0.1.0 origin/main -m "lotor 0.1.0 — préversion du lot 1"` ;
   3. `git push origin v0.1.0` ;
   4. suivre le workflow **release** (onglet *Actions*) ; vérifier sur la page *Releases*
      une **préversion** `v0.1.0` portant six archives `.tar.gz` (trois rôles × amd64,
      arm64), quatre paquets (`.deb`, `.rpm` × amd64, arm64) et `SHA256SUMS` ; contrôler
      un téléchargement par `sha256sum -c --ignore-missing SHA256SUMS` ;
   5. cocher le critère « `v0.1.0` publiée » de [T11](lots/T11-recette-lot-1.md).
   En cas d'échec du workflow : corriger par un commit sur `main` et poser `v0.1.1` (ne
   jamais déplacer une étiquette poussée).
7. Facultatif : rejouer les mesures sur la machine de référence (16 cœurs) par les
   commandes de [`docs/benchmarks.md`](../docs/benchmarks.md) ; elles tiennent déjà sur
   4 cœurs.

### Organisation

- Chaque lot est réalisé par un agent au contexte neuf, qui lit `CLAUDE.md`,
  l'architecture, `specs/lecons.md`, sa fiche et le Journal des lots dont il dépend.
- Les lots indépendants avancent en parallèle (T02 et T03 ; T06, T07 et T08 ; T09 et T10),
  chacun sur sa branche `lot/<id>-<sujet>` et sa PR.
- Une PR est fusionnée en « squash » dès que la CI est verte et les critères cochés.
