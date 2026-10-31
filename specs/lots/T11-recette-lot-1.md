# T11 — Recette du lot 1

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T07, T08, T09, T10 | En cours |

## Objectif

Passer le critère du lot 1 : **un parc pilote inventorié et interrogé**. Durcir, mesurer,
documenter et publier une préversion.

## Périmètre

**Inclus**

- Écrans d'administration d'instance : traitements en échec (relancer, abandonner), état de
  la base de vulnérabilités (version cible, version de chaque instance, âge, dernière mise à
  jour) et import manuel d'une archive.
- Mesures consolidées des cibles du cahier des charges selon `docs/benchmarks.md` :
  ingestion et analyse de 5 000 composants, recherche, tableau de bord, scan de l'agent
  serveur.
- Revue de sécurité de tout le lot 1 par un relecteur distinct de l'auteur, gravité selon
  l'OWASP Risk Rating ; mise à jour du modèle de menace ; correction des constats.
- Audit RGAA de tous les écrans du lot 1 (grille consignée) ; corrections.
- Point sur les évolutions d'open-go-base du § 23 de l'architecture attendues avant ce lot
  (codes de secours de mfax).
- `docs/operations.md` complet pour le lot 1 ; guide de démarrage utilisateur (FR et EN).
- Déploiement pilote et recette sur le périmètre défini avec l'utilisateur.
- Préversion `v0.1.0` : `CHANGELOG.md`, étiquette, binaires.

**Exclu** : toute nouvelle fonction.

## Critères d'acceptation

- [ ] Toutes les cibles chiffrées sont tenues au 95e centile sur la machine de référence,
      ou une nouvelle cible a été validée par l'utilisateur et reportée au cahier des
      charges.
- [ ] Aucune faiblesse de gravité haute ou critique (OWASP Risk Rating) ouverte à l'issue de
      la revue.
- [x] Grille RGAA remplie pour chaque écran, sans non-conformité bloquante
      ([grille](../../docs/accessibilite/grille-rgaa-lot1.md) : 100 % des critères
      applicables après corrections, aucune NC bloquante ni avant ni après).
- [ ] Sur le parc pilote : tous les serveurs et dépôts prévus ont un instantané de moins de
      24 h.
- [ ] Pour trois CVE choisies avant la recette, la recherche renvoie exactement la liste de
      projets attendue, établie à la main au préalable.
- [ ] `v0.1.0` publiée.

## Décisions

Prises le 31 octobre 2026 :

- Parc pilote de démonstration : conteneurs Debian, Rocky Linux (famille RHEL) et Alpine
  portant l'agent serveur, et dépôts publics sur GitHub et GitLab. La liste exacte et les
  CVE de contrôle sont fixées au début du lot, avant toute recherche.
- `v0.1.0` publiée en préversion sur GitHub Releases : étiquette, binaires des trois rôles,
  sommes de contrôle.

## Journal

Le lot est réalisé en deux parties : la partie 1 (branche `lot/T11-administration`)
livre les écrans d'administration d'instance et les corrections techniques en attente ;
la partie 2 (branche `lot/T11-recette`) traite la revue de sécurité, l'audit RGAA, les
mesures, le parc pilote et la préversion. Les critères d'acceptation ci-dessus relèvent
de la partie 2.

### Partie 1 — Administration de l'instance et corrections

Réalisée le 31 octobre 2026, branche `lot/T11-administration`.

#### Livré

- **Traitements en échec** (`/admin/jobs`, administrateurs d'instance) : compteurs de la
  file (en attente, en cours, en échec), jobs morts paginés (type, clé, organisation lue
  sous sa RLS, tentatives, date, dernière erreur), **Relancer** et **Abandonner** en `POST`
  avec CSRF ; chaque action verrouille le job (`jobs.GetDead … FOR UPDATE`), l'applique et
  écrit l'entrée d'audit d'instance (`job.retried`, `job.discarded`) dans la même
  transaction ; un double envoi répond 404 avec un message. `internal/jobs` :
  `GetDead`, `CountJobs`, `Active`.
- **État de la base de vulnérabilités** (`/admin/vulndb`) : âge de la cible ajouté ;
  **version chargée par chaque instance worker** (à jour, en retard, sans base, sans
  nouvelles ; date de construction et âge de la base chargée, date de chargement, dernier
  signal, erreur de synchronisation), rapportée par `vuln.Manager` après chaque
  synchronisation dans la nouvelle table globale `vulndb_instances`, retirée à l'arrêt.
- **Import manuel d'une archive** : formulaire multipart sur le même écran ; fichier lu
  en flux (`uploadGate`, jeton CSRF en première partie présenté à csrfx), rangé par blocs
  de 8 Mio dans PostgreSQL (`vulndb_imports`, `vulndb_import_chunks`), un bloc par
  transaction ; job `vulndb.import` (`Checker.ImportHandler`) qui recopie, vérifie,
  installe (`Checker.Import`) et fait de l'archive la cible ; un seul import à la fois ;
  imports bloqués abandonnés au suivant ; état des cinq derniers imports affiché ; demande
  et issue journalisées (`vulndb.import_requested`, `vulndb.imported`,
  `vulndb.import_failed`). Nouvelle erreur `vuln.ErrInvalidArchive`.
- **Purge des archives** qui ne sont pas la cible (`vuln.PurgeArchives`), formulaire avec
  case de confirmation, journalisée (`vulndb.archives_purged`) — écart laissé par T06.
- Migration **014** (`vulndb_instances`, `vulndb_imports`, `vulndb_import_chunks`,
  tables globales). Traductions fr et en (`admin_jobs.*`, `admin_vulndb.*`, `flash.*`,
  `audit.action.*`, `nav.admin_jobs`). CSS : `.input--file`.
- **Défaut mobile** (bande vide sous la navigation latérale à 390 px, toutes les pages à
  navigation) : `.shell` est en `flex-wrap: wrap` et `flex: 1` dans un `body` à hauteur
  d'écran ; sous 64rem la navigation passe sur sa propre ligne et `align-content` par
  défaut (`normal`, soit `stretch`) partage la hauteur libre entre les deux lignes.
  Correctif : `align-content: flex-start` dans `@container ogsbom (width < 64rem)`
  seulement (au-dessus, la ligne unique étirée garde la navigation sur toute la hauteur).
  Avec les deux défauts voisins signalés par l'audit RGAA : `min-width: 0` sur `.sidenav`
  dans le même bloc (défilement horizontal à 320/390 px) et `position: relative` sur
  `.table-wrap` (les `.visually-hidden` débordaient la zone défilante). Vérifié par
  captures Playwright (Chromium), thèmes clair et sombre, 390 et 1 280 px, pages
  `/o/<slug>`, membres, traitements, base : à 390 px, navigation de 47 px collée au
  contenu (122 px sur la page des membres en rétablissant `align-content: normal`, plus
  sur une page courte), aucun défilement horizontal ; à 1 280 px, navigation sur toute la
  hauteur.
- **Test instable `TestLostLeaseCancelsHandler`** : reproduit (3 échecs sur 30, « statut
  pending ») avec `-race`, `GOMAXPROCS=1` et `taskset -c 0` partagé avec 40 boucles
  actives. Cause **dans le test** : il simulait la reprise par un autre worker en changeant
  le seul jeton du bail, laissant `locked_until` expirer 300 ms plus tard ; sous charge,
  le même runner reprenait le job expiré (deuxième exécution du handler, `close` d'un
  canal déjà fermé, panique, nouvel essai) avant la vérification, faite après un
  `time.Sleep(50 ms)`. Le code est correct (la reprise d'un bail expiré est voulue).
  Correctif : l'autre worker pose son jeton **et** son bail (une heure) ; bail du test
  porté à 3 s (renouvelé chaque seconde) pour qu'un renouvellement retardé ne perde pas le
  bail avant la simulation ; attente déterministe de l'issue `lost` dans
  `ogsbom_job_runs_total` au lieu du `sleep` ; le test vérifie en plus le jeton, le bail,
  les tentatives, l'absence d'erreur enregistrée et une seule exécution du handler. Après
  correctif : 50 passages sur 50 dans les mêmes conditions. Ce que le test prouve est
  inchangé (annulation du handler sur perte de bail, résultat ignoré).
- **Point open-go-base § 23 (codes de secours de mfax)** : constaté **absent** — ni
  v1.0.1, ni la pseudo-version utilisée (`v1.0.2-0.20261031043924-3534c1429b63`, commit
  `3534c14`), ni `main` d'open-go-base ne contiennent de codes de secours (aucune
  occurrence de « recovery », « backup », « secours » dans `mfax`). Non nécessaire au
  critère du lot 1 : la récupération passe par la réinitialisation du TOTP par un
  administrateur d'instance (auditée) et par la procédure de secours (ADR 0013). Aucune
  évolution ouverte ; § 23 de l'architecture mis à jour (reporté à T18).
- Docs : ADR 0028, `architecture.md` (§ 8, § 12, § 14, § 23), `docs/operations.md`
  (traitements en échec, état des instances, import, purge, mandataire inverse),
  `config.example.yaml` et aide de `vulndb.download_timeout`, `doc.go` de `jobs` et
  `vuln`.

#### Tests

- `jobs` (intégration) : `CountJobs`, `Active`, `GetDead` ; `TestLostLeaseCancelsHandler`
  réécrit.
- `vuln` (intégration) : téléversement et job d'import (blocs, journal, second import
  refusé, installation sur une autre instance, blocs supprimés, rejeu, réimport du même
  fichier) ; refus (vide, trop gros, lecture interrompue : rien ne reste) ; imports
  bloqués abandonnés (téléversement interrompu, job disparu) et téléversement récent
  bloquant ; échecs du job (archive invalide sans nouvel essai, erreur passagère
  réessayée puis échec à la dernière tentative, charge illisible permanente, import
  inconnu) ; purge (cible gardée, octets comptés, journal, cible encore synchronisable) ;
  rapport et retrait de l'instance, ligne de plus de 7 jours supprimée.
- `web` (intégration) : écran des traitements (fr, en, accessibilité, absence de code en
  ligne, erreur échappée, relance, double relance, abandon, identifiants invalides, refus
  sans CSRF, journal) ; import (jeton faux, jeton après le fichier, sans fichier, compte
  ordinaire 404, trop gros 413, rien stocké après les refus ; import accepté, job en file,
  écran « en cours » sans formulaire, second import 409 ; installation par le job, écran et
  journal) ; purge (confirmation exigée, purge, journal) et états des instances ; nouvelles
  routes dans le parcours des routes d'administration (404 pour un compte ordinaire) et
  dans `TestEveryScreenIsAccessible` (fr, en, clair, sombre).

#### Décisions

- **ADR 0028** **[à relire]** : archive téléversée rangée dans PostgreSQL puis installée
  par un job (instance web et worker séparables) ; lecture en flux avec jeton CSRF en
  première partie présenté à csrfx par son en-tête (seule route dont le jeton n'est pas lu
  dans le corps par csrfx) ; un bloc par transaction ; un seul import à la fois ; archive
  importée cible **même plus ancienne** que la cible actuelle (retour arrière volontaire,
  annoncé à l'écran) ; 3 tentatives pour le job d'import, archive invalide refusée sans
  nouvel essai ; état par instance dans `vulndb_instances`, instance nommée hôte:PID,
  « sans nouvelles » au-delà de max(3 × `sync_interval`, 15 min), ligne oubliée après
  7 jours ; purge de **toutes** les archives non cibles, avec case de confirmation.
- `vulndb.download_timeout` borne aussi la durée d'un téléversement (pas de nouveau
  réglage) **[à relire]**.
- Abandon d'un traitement sans confirmation (action ciblée, réversible par une nouvelle
  mise en file de la donnée qui l'a produit) ; purge avec confirmation (irréversible)
  **[à relire]**.
- Codes de secours de mfax reportés à T18, sans évolution d'open-go-base pour le lot 1
  **[à relire]**.

#### Écarts

- Aucun pour le périmètre de la partie 1. `TestLeaseIsRenewedWhileHandlerRuns` garde un
  bail de 300 ms : il n'a pas échoué dans les mêmes conditions de charge, mais repose sur
  le même équilibre (voir `specs/lecons.md`).

#### ADR créés

0028.

### Audit RGAA

Réalisé le 31 octobre 2026, branche `lot/T11-accessibilite`. Grille finale :
[`docs/accessibilite/grille-rgaa-lot1.md`](../../docs/accessibilite/grille-rgaa-lot1.md).

#### Résultat

Audit initial sur `main` (8369ad0) : 85,7 % (60 critères conformes sur 70 applicables),
13 constats, 0 bloquant, 4 majeurs, 9 mineurs. Après corrections : **100 %** (72 sur 72 ;
12.3 et 12.4 deviennent applicables avec le plan du site), aucun constat ouvert. Contre-audit
outillé sur 88 pages, les 11 pages de confirmation et le plan du site, en français et en
anglais, thèmes clair et sombre : axe-core sans aucun écart (368 rendus), aucun défilement
horizontal à 320 et 390 px ni à 200 % de texte, parcours clavier sans piège, captures de
contrôle des écrans corrigés dans les deux thèmes.

| NC | Gravité | Critère | Statut | Commit |
| --- | --- | --- | --- | --- |
| NC-01 navigation latérale trop large | majeure | 10.11 | corrigé, vérifié | PR #13 |
| NC-02 texte masqué hors des tableaux | majeure | 10.11 | corrigé, vérifié | PR #13 |
| bande vide sous la navigation | défaut | 10.11 | corrigé, vérifié | PR #13 |
| NC-03 menu d'organisation à 320 px | mineure | 10.11 | corrigé | 9bd0e4a |
| NC-04 PURL insécable | mineure | 10.11 | corrigé | 9bd0e4a |
| NC-05 compteurs de sévérité sans libellé | majeure | 3.1, 10.9, 10.10 | corrigé | 9bd0e4a |
| NC-06 ligne sélectionnée par la couleur | mineure | 3.1 | corrigé | 9bd0e4a |
| NC-07 version vulnérable par la couleur | mineure | 3.1 | corrigé | 9bd0e4a |
| NC-08 titres peu discriminants | mineure | 8.6 | corrigé | 9bd0e4a |
| NC-09 noms de langue sans `lang` | mineure | 8.7 | corrigé | 9bd0e4a |
| NC-10 bouton « Modifier » sans contexte | mineure | 11.9 | corrigé | 9bd0e4a |
| NC-11 format attendu masqué | mineure | 11.10 | corrigé | 9bd0e4a |
| NC-12 actions irréversibles en un clic | majeure | 11.12 | corrigé | 9bd0e4a |
| NC-13 un seul système de navigation | mineure | 12.1 | corrigé | 9bd0e4a |

#### Livré

- **Confirmation des actions irréversibles** (NC-12) : `GET` sur l'URL de l'action →
  page commune `confirm/action` (`internal/web/confirm_pages.go`), `POST` sur la même URL
  → action ; lien « Annuler ». Jetons d'agent, d'inscription et personnels, désactivation
  d'un agent, retrait d'un membre (texte propre pour soi-même), réinitialisation du mot de
  passe et du TOTP, abandon d'un traitement en échec. Les `POST` existants sont inchangés.
  Nouvelle lecture `org.Service.Member`.
- **Titres de page** (NC-08) : « écran — organisation » par le layout (organisation
  courante de l'en-tête), requête de la recherche, préfixe « Erreur : » posé par
  `render.Render` pour un écran rendu en 4xx (`render.Page.Failed`, jamais sur les pages
  d'erreur) ; `dashboard.title` ne répète plus le nom.
- **Plan du site** (NC-13) : `/sitemap`, lié du pied de page des sessions complètes
  (`render.Chrome.Authenticated`), construit par `orgNav` (selon le rôle dans chaque
  organisation), `accountNav` et `adminNav`.
- Présentation : sélecteur d'organisation (NC-03), en-tête de page (NC-04), compteurs de
  sévérité abrégés et repliables (NC-05), ligne sélectionnée (NC-06), répartition des
  versions (NC-07), `lang` des noms de langue (NC-09, option `option.Lang`), « Modifier le
  rôle » et colonne Actions des membres de nouveau lisible (NC-10 ; le bouton était
  recouvert par « Retirer »), aide des étiquettes visible (NC-11).
- Recommandations traitées : zones défilantes de tableau en `role="group"` nommé et
  focalisable partout (R-01, R-06), espaces entre texte masqué et visible (R-05), couleur
  des textes indicatifs (R-11), aide de l'import de la base liée au champ.
- Garde-fous : `webtest.CheckAccessibility` refuse une aide `aria-describedby` masquée
  visuellement et une option de `<select name="language">` sans `lang` égal à sa valeur ;
  tests d'intégration `TestIrreversibleActionsAreConfirmed` (lien, page sans effet,
  fr/en, accessibilité, `POST`, objet déjà révoqué, 404), `TestPageTitlesAreDistinct`,
  `TestSiteMap`, assertions de `TestFindingScreens` ; `TestRenderTitle` ; les nouvelles
  routes `GET` passent dans les harnais d'isolement par route et d'administration.
- Clés de traduction (fr, en) : `layout.title_org`, `layout.title_error`,
  `search.title_query`, `severity_short.*`, `component.this_version`,
  `snapshots.ref_shown`, `footer.sitemap`, `sitemap.*`, `confirm.*` ;
  `members.change_role` et `dashboard.title` modifiées.
- `architecture.md` § 14 : conventions issues de l'audit (actions irréversibles, titres,
  plan du site, zones de tableau).

#### Décisions

- **Page de confirmation plutôt que case « je confirme »** **[à relire]** : un seul
  gabarit et une seule fonction pour toutes les actions, l'objet et les conséquences
  écrits en toutes lettres, aucune modification des `POST` existants (moins de conflits
  avec la revue de sécurité menée en parallèle), et une case dans chaque ligne de tableau
  aurait alourdi les listes. Prix : un aller-retour de plus. La purge des archives garde
  sa case (partie 1), conforme elle aussi.
- **Abandon d'un traitement confirmé** **[à relire]** : il supprime le job et sa dernière
  erreur (irréversible pour l'administrateur) ; revient sur la décision de la partie 1
  (« sans confirmation »). « Relancer » reste en un clic.
- **NC-13 : plan du site** plutôt que la recherche comme second système **[à relire]** :
  la recherche transverse cherche des composants et des vulnérabilités, pas des pages ;
  elle ne satisfait pas 12.1. Plan simple, sans nouvelle donnée, réservé aux sessions
  complètes.
- **« Erreur : » sur tout écran rendu en 4xx** **[à relire]** : règle centrale dans
  `render` plutôt qu'écran par écran ; vaut aussi pour une recherche illisible (400) et
  l'écran des traitements renvoyé en 404 après un double envoi.
- **Abréviations des sévérités** (« Crit. », « Élev. », « Moy. », « Faible » ; « Crit »,
  « High », « Med », « Low ») avec le libellé complet en `title` et pour les lecteurs
  d'écran **[à relire]**.
- Pas d'ADR : pas de décision structurante au-delà des conventions consignées au § 14.
- Pas de test Playwright dans le dépôt : la CI n'a pas de navigateur et le brief exclut
  toute nouvelle dépendance ; la redistribution à 320 px reste vérifiée à l'audit
  (scripts hors dépôt), les règles statiques sont dans `webtest`.

#### Écarts

- Recommandations R-02, R-03, R-04, R-07, R-08, R-09, R-10 non traitées (hors grille,
  listées au § 6 de la grille).

#### ADR créés

Aucun.
