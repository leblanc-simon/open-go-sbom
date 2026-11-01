# T14 — Triage et VEX

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | Terminé |

## Objectif

Permettre aux analystes de qualifier chaque constat, pour un projet ou pour toute
l'organisation, avec un historique complet, et échanger ces qualifications au format VEX.

## Périmètre

**Inclus**

- `internal/triage` : décisions avec statut (à analyser, affecté, non affecté, faux positif,
  risque accepté, corrigé), justification VEX pour « non affecté », déclaration d'impact,
  date d'expiration pour « risque accepté », portée (projet ou organisation), auteur, date.
- Historique en ajout seul ; statut effectif calculé : décision du projet, sinon décision de
  l'organisation, sinon « à analyser ».
- Job d'expiration : un risque accepté échu revient « à analyser » et laisse une trace.
- Écrans : panneau de triage (rôle `analyst` ou `admin`), historique, filtres par statut
  effectif ; les constats « non affecté » et « faux positif » sont masqués par défaut.
- Export OpenVEX et CycloneDX VEX d'un projet ; import de VEX d'éditeurs (décisions
  d'auteur `vex:<source>`).
- Audit de chaque décision.

**Exclu** : alertes sur changement de statut (T15).

## Conception

- Les décisions s'appliquent au niveau des constats, après la correspondance : l'adaptateur
  Grype reste pur et une décision s'applique aussi aux constats futurs du même couple
  (composant, vulnérabilité). Ce choix est consigné en ADR ; il remplace la réinjection
  dans Grype évoquée au cahier des charges, avec le même effet pour l'utilisateur.
- Une décision d'organisation vise un couple (`purl_base`, vulnérabilité), éventuellement
  restreint à une plage de versions `vers`.
- Justifications : OpenVEX et CycloneDX n'ont pas les mêmes listes (OpenVEX :
  `component_not_present`, `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`,
  `inline_mitigations_already_exist` ; CycloneDX : `code_not_present`, `code_not_reachable`,
  `requires_configuration`, `requires_dependency`, `requires_environment`,
  `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`,
  `protected_by_mitigating_control`). Le projet stocke la justification d'origine telle
  quelle et documente une table de correspondance ; un export vers l'autre format note la
  justification d'origine quand la correspondance perd de l'information.

## Livrables

Paquet, migrations, écrans, routes d'API, exports et imports, ADR.

## Maquettes

Planches « 6 · Triage d'un constat » du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Une décision d'organisation s'applique à tous les projets concernés, et une décision de
      projet la surcharge pour ce projet seulement.
- [x] Un constat apparu après une décision hérite de son statut.
- [x] Un risque accepté échu revient « à analyser » le jour même.
- [x] Les exports VEX sont valides contre les schémas OpenVEX et CycloneDX.
- [x] Un aller-retour export puis import dans le même format redonne les mêmes décisions,
      justifications comprises.
- [x] Un `viewer` ne peut pas trier (rôle d'équipe `reader` depuis T16 : 403, et aucun
      panneau de triage sur la fiche).

## Tests attendus

Tables de calcul du statut effectif ; validation des exports par schéma ; import de VEX
d'exemple ; isolement.

## Points à trancher

Aucun.

## Journal

Réalisé le 1er novembre 2026, branche `lot/T14-triage-vex`, en autonomie (lot 2 enchaîné
sans attendre l'utilisateur, en parallèle de T12, T13 et T17) : les décisions marquées
**[à relire]** n'ont pas été validées explicitement.

### Livré

- Migration **018** (`018_triage.sql`, numérotée 017 avant la fusion de T17) : table d'organisation `triage_decisions` (RLS
  standard, clés composites vers `projects` et vers elle-même pour une échéance,
  contraintes de cohérence portée / action / statut / justification / échéance), **en
  ajout seul** pour le rôle d'exécution (`REVOKE UPDATE, DELETE, TRUNCATE`, vérifié par
  `CheckRuntimeRole` comme le journal d'audit) ; colonnes `findings.triage_status` et
  `triage_decision_id` ; index du couple (`purl_base`, vulnérabilité), des décisions d'un
  projet, du filtre par statut et des constats d'une décision.
- `internal/triage` : statuts (`Status`, `Hidden`), justifications des deux listes et
  table de correspondance (`Justification.In`, `Lossless`), décisions et décision
  courante d'une clé (`Current`), statut effectif (`Resolver.Resolve`, plages `vers` par
  `internal/version`), service : `Decide`, `Withdraw`, `Current`, `Import`, `Statements`,
  `History`, `PairCount`, `OrgDecisions`, `Classify` (appelé par `finding.Analyzer` dans
  sa transaction), job `triage.expire` (`ExpireHandler`, `Expire`), point d'accroche
  `Options.OnChange` ; verrou consultatif par organisation (exclusif pour une décision,
  partagé pour une analyse).
- `internal/triage/vex` : OpenVEX 0.2.0 (structures propres, schéma officiel embarqué,
  licence CC0, `OpenVEXValidator`) et CycloneDX 1.6 (`cyclonedx-go`) : `Encode`,
  `Export`, `Decode` (format reconnu au contenu, bornes, déclarations inconnues
  écartées et comptées), marques `[lotor:…]` dans `status_notes` et propriétés `lotor:`.
- `internal/finding` : `Row` porte le statut de triage, filtre par statut
  (`Filter.Triage`, `HideMuted`), décompte des constats masqués (`Counts.Muted`), `Get`,
  `Events`, interface `Classifier` et classement des constats créés ou rouverts.
- `internal/tenant` : permission d'organisation `triage.org` (administrateurs) ;
  `finding.triage` couvre aussi l'import d'un VEX de projet et le retrait d'une décision
  du projet ; `docs/security/permissions.md` régénéré.
- `internal/web` : fiche d'un constat (`/projects/{p}/findings/{id}` : résumé, panneau de
  triage, historique fusionnant décisions et événements de l'analyse), décision
  (`…/triage`), retrait avec confirmation (`/projects/{p}/decisions/{id}/withdraw`,
  `/triage/decisions/{id}/withdraw`), onglet « VEX » d'un projet (export, import),
  rubrique « Triage » de l'organisation (décisions en vigueur, import d'organisation) ;
  colonne et filtre de triage dans l'onglet « Constats » (non affectés et faux positifs
  masqués par défaut, avec leur nombre) et colonne sur la fiche vulnérabilité ; import
  borné à 1 Mio par `uploadGate` pour un compte authentifié ; composants CSS
  `choice-list`, `timeline`, statuts de triage, écran `triage.css` ; traductions FR et EN.
- `internal/api` : `GET /api/v1/orgs/{org}/projects/{project}/vex?format=openvex|cyclonedx`
  (contrat OpenAPI, code généré), 404 `error.vex_empty` sans décision.
- `internal/dashboard` : les constats « non affecté » et « faux positif » ne comptent plus
  parmi les constats ouverts (indicateurs et statistiques quotidiennes).
- Audit : `triage.decided`, `triage.withdrawn`, `triage.expired`, `triage.vex_imported`.
- Docs : ADR 0035, 0036, 0037 ; `architecture.md` (§ 3, 8, 10, 12, 14, 15, 19) ;
  `docs/utilisation.md` (triage, VEX, table de correspondance) ; `docs/operations.md`
  (échéances, borne d'import, migration) ; modèle de menace (trois menaces) ;
  `CHANGELOG.md` ; `doc.go` de `triage` et `triage/vex`.

### Intégration avec T17 (fusionné pendant le lot)

- Migration renumérotée **018** après la fusion de T17 (`017_snapshot_history.sql`).
- L'effet sur la sécurité d'une comparaison d'instantanés (`finding.SnapshotEffect`)
  ignore les constats « non affecté » et « faux positif » : ni introduits ni résolus
  (`TestEffectIgnoresMutedFindings`) **[à relire]**.
- La rétention de T17 met `findings.snapshot_id` à nul quand elle supprime un instantané :
  le triage n'en dépend pas (décisions rattachées au projet, au purl et à la
  vulnérabilité ; statut effectif sur le constat, qui reste).

### Pour T15 (politiques et alertes)

À réutiliser plutôt qu'à refaire (détail dans le `doc.go` de `internal/triage`) :

- statut effectif d'un constat : `findings.triage_status` (`triage.Status`) ; une règle sur
  les constats « actionnables » filtre `triage_status NOT IN ('not_affected',
  'false_positive')` (`triage.HiddenStatuses`), comme le tableau de bord ;
- changements de statut : `triage.Options.OnChange(ctx, tx, []triage.Change)`, appelé dans
  la transaction qui change le statut (décision, retrait, import, échéance, classement
  d'un constat nouveau) — y mettre en file l'alerte « changement de statut » ;
- événements : le journal `triage_decisions` (une ligne datée et signée par décision,
  retrait, échéance) et `triage.Service.History` pour un constat ; audit
  `triage.*` ;
- échéances : job `triage.expire`, idempotent.

### Tests

- `internal/triage` (unitaires) : **table du statut effectif**
  (`TestEffectiveStatusTable` : 16 cas — projet, organisation, surcharge, autre projet,
  autre version, plus récente, retraits, échéance, plages contenant ou non la version,
  autre schéma, plage illisible, plusieurs plages), départage à date égale, échéance,
  statuts ; **table de correspondance** des justifications (`Lossless` exact pour les 14).
- `internal/triage/vex` : **exports valides** contre le schéma OpenVEX 0.2.0 et le schéma
  CycloneDX 1.6 strict, chaque statut et chaque justification ; **aller-retour** dans le
  même format et d'un format à l'autre ; justification d'origine notée ; **VEX
  d'éditeurs** OpenVEX (sous-composants, `identifiers.purl`, produit sans version,
  produit sans purl) et CycloneDX 1.5 (références par `bom-ref` et par purl,
  vulnérabilité sans analyse) ; documents refusés, bornes ; `FuzzDecode`.
- `internal/triage` (intégration) : décision d'organisation appliquée à tous les projets
  et surchargée par un projet, retraits, journal en ajout seul, audit, `OnChange` ; plage
  `vers` ; héritage par `Classify` ; **échéance le jour même** (job à minuit UTC, rien à
  23 h 59, retour à 00 h 01, trace système, idempotence) ; validation ; **isolement**
  entre organisations ; **aller-retour VEX** par le service (OpenVEX et CycloneDX : six
  décisions de statuts et justifications variés rétablies à l'identique) ; import
  d'éditeur pour l'organisation et pour un projet.
- `internal/finding` : `TestNewFindingInheritsTriageDecision` (vrai `Analyzer`, second
  projet analysé après une décision d'organisation) — vérifié en coupant l'appel à
  `Classify` : échec.
- `internal/dashboard` : `TestMutedFindingsLeaveIndicators`.
- `internal/db` : harnais RLS étendu à `triage_decisions` (en ajout seul) ;
  `CheckRuntimeRole` refuse un `DELETE` accordé sur le journal des décisions.
- `internal/web` : `TestTriageScreens` (fiche, panneau, refus d'un lecteur et d'une
  décision d'organisation par un analyste en 403, validation, masquage par défaut,
  filtres, décision d'organisation par l'administrateur, retrait avec confirmation,
  exports validés par schéma, réimport, import d'organisation, API par jeton personnel,
  isolement entre organisations ; deux langues, accessibilité, CSP, pour trois rôles) ;
  harnais d'isolement par route et `TestRoutePermissionsFollowMatrix` couvrent les
  nouvelles routes.

### Décisions

Décisions de la fiche appliquées telles quelles (décisions après la correspondance,
portée organisation sur `purl_base` et `vers`, justification d'origine conservée avec
table de correspondance). Décisions prises pendant le lot, toutes **[à relire]** :

- **Statut effectif rangé sur chaque constat**, recalculé en Go à chaque décision et à la
  création d'un constat, plutôt que calculé à la lecture ; verrou consultatif par
  organisation contre la course décision / analyse
  ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **Journal en ajout seul** avec retrait explicite ; une échéance ramène « à analyser » à
  sa portée (elle masque la décision d'organisation pour ce projet jusqu'à la décision
  suivante) ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **Clé d'une décision de projet** : le purl canonique du composant (version et
  qualificatifs compris) ; une montée de version demande une nouvelle décision
  ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **Permission `triage.org`** réservée aux administrateurs de l'organisation ; la liste
  des décisions d'organisation aussi ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **Échéance par un job par décision** (`triage.expire`, lendemain à minuit UTC), sans
  balayage horaire ; risque accepté borné à 3 ans
  ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **Audit d'un import** : un événement avec ses décomptes, chaque décision importée
  portant `vex:<source>` et le compte importateur ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **Tableau de bord** sans les constats « non affecté » et « faux positif »
  ([ADR 0035](../../docs/adr/0035-decisions-de-triage.md)).
- **VEX** : structures OpenVEX propres (`openvex/go-vex` écarté), `cyclonedx-go` pour
  CycloneDX ; correspondance des statuts (faux positif et risque accepté par des marques
  `[lotor:…]` en OpenVEX, propriétés `lotor:` en CycloneDX) ; justification d'origine
  **toujours** notée quand elle change de liste ; export limité aux constats ouverts qui
  ont une décision ; import de projet par famille, version et qualificatifs compatibles ;
  bornes 1 Mio et 5 000 déclarations ; pas d'import par l'API (jetons en lecture seule)
  ([ADR 0036](../../docs/adr/0036-echanges-vex.md)).
- **Écrans** : fiche du constat en page plutôt qu'en tiroir modal, champs révélés par
  `:has()`, justification et commentaire exigés dans l'interface, deux vocabulaires de
  justification proposés, « assignation à une équipe » de la maquette non reprise,
  retrait par la page de confirmation, onglet VEX, rubrique Triage
  ([ADR 0037](../../docs/adr/0037-ecrans-du-triage.md)).

### Écarts

- La maquette ouvre le triage en tiroir ; il est livré en page (ADR 0037).
- Captures d'écran (fiche du constat en clair, sombre et mobile 390 px ; onglet des
  constats, onglet VEX, rubrique Triage en sombre) faites par un test temporaire non
  commité et relues ; non versionnées. L'audit RGAA manuel du lot 2 (T18) couvrira ces
  écrans.
- Recherche : le cahier des charges affiche le statut de triage dans les résultats d'une
  recherche par vulnérabilité ; non livré ici (la recherche n'a pas changé), à reprendre
  en T18 avec le filtre d'équipe laissé par T16.
- Les statistiques quotidiennes déjà enregistrées ne sont pas réécrites (seules les
  suivantes excluent les constats masqués).

### ADR créés

- [0035 — Décisions de triage](../../docs/adr/0035-decisions-de-triage.md).
- [0036 — Échanges VEX](../../docs/adr/0036-echanges-vex.md).
- [0037 — Écrans du triage](../../docs/adr/0037-ecrans-du-triage.md).

Aucune nouvelle fonction `crossorg`, aucune nouvelle dépendance tierce.
