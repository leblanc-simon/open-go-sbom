# 0035 — Décisions de triage appliquées aux constats, statut effectif rangé sur chaque constat, journal en ajout seul

- Statut : Accepté
- Date : 2026-11-01
- Lot : T14

## Contexte

Le cahier des charges (§ 7) veut qualifier chaque constat — à analyser, affecté, non
affecté (justification VEX), faux positif, risque accepté jusqu'à une date, corrigé —
pour un projet ou pour tous les projets de l'organisation qui partagent le composant, et
évoque des « décisions réinjectées dans Grype pour ne plus remonter ». La fiche T14 fixe
la conception : les décisions s'appliquent au niveau des constats, après la
correspondance, l'adaptateur Grype reste pur, une décision vaut aussi pour les constats
futurs du même couple, une décision d'organisation vise (`purl_base`, vulnérabilité)
éventuellement restreint à une plage `vers`, l'historique est en ajout seul, et le
statut effectif se calcule : projet, sinon organisation, sinon « à analyser ».

Restait à décider où vit le statut effectif, comment il suit les décisions et les
nouveaux constats, comment une échéance s'applique « le jour même », et qui décide pour
toute l'organisation.

## Décision

### Modèle

- Table d'organisation `triage_decisions` (RLS standard, clés composites) : portée
  (`project` : projet et purl canonique du composant ; `org` : `purl_base` et plage
  `vers` normalisée ou nulle), vulnérabilité, action (`set`, `withdraw`, `expire`),
  statut, justification d'origine telle quelle (liste OpenVEX ou CycloneDX, ADR 0036),
  commentaire (déclaration d'impact), dernier jour d'acceptation d'un risque, auteur
  (compte, et libellé : e-mail, `vex:<source>` pour un import, `system` pour une
  échéance), date.
- **Journal en ajout seul** : le rôle d'exécution n'a ni `UPDATE`, ni `DELETE`, ni
  `TRUNCATE` sur la table (migration 018), ce que `CheckRuntimeRole` vérifie au démarrage
  comme pour le journal d'audit (ADR 0030). Une décision, un retrait ou une échéance
  ajoute une ligne ; la décision courante d'une clé (portée, projet, purl ou `purl_base`
  et plage, vulnérabilité) est la plus récente (date, puis UUID v7).
- Un projet hérite de l'organisation tant qu'il n'a pas sa propre décision ; un
  **retrait** (`withdraw`) rend la main (au niveau organisation, ou « à analyser »). Une
  échéance (`expire`) n'est pas un retrait : elle ramène le couple « à analyser » à sa
  portée, comme le veut la fiche, et masque donc une décision d'organisation pour un
  projet dont le risque accepté a échu, jusqu'à la décision suivante.

### Statut effectif rangé sur chaque constat

- `findings.triage_status` et `findings.triage_decision_id` portent le statut effectif
  et la décision qui le donne. Écrans, filtres, décomptes, exports, tableau de bord et
  bientôt politiques (T15) le lisent sans recalcul.
- Il est recalculé par `internal/triage`, en Go (la comparaison de versions d'une plage
  `vers` passe par `internal/version`, ADR 0026, impossible en SQL) :
  - à chaque décision, retrait, import ou échéance, pour tous les constats du couple
    (`purl_base`, vulnérabilité) de l'organisation, dans la transaction de la décision ;
  - à la création ou à la réouverture d'un constat, par `finding.Analyzer`, qui appelle
    `triage.Service.Classify` dans la transaction où il écrit les constats (interface
    `finding.Classifier`) : un constat apparu après une décision en hérite, sans que
    l'adaptateur Grype en sache rien.
- **Verrou consultatif par organisation** : une décision prend
  `pg_advisory_xact_lock`, la classification d'une analyse
  `pg_advisory_xact_lock_shared`, avant de lire les décisions. Sans lui, un constat
  inséré par une analyse en cours échapperait au recalcul d'une décision validée
  entre-temps (deux transactions en `READ COMMITTED` qui ne voient pas les écritures de
  l'autre). Les analyses ne se bloquent pas entre elles ; une décision attend la fin des
  analyses en cours, qui sont courtes à l'écriture.
- Chaque changement de statut effectif est rendu à `triage.Options.OnChange`, dans la
  transaction qui le produit : c'est le point d'accroche des alertes de T15.

### Échéance d'un risque accepté

Un job `triage.expire` est mis en file avec la décision, pour le lendemain du dernier
jour d'acceptation à minuit UTC (clé d'unicité `decision:<id>`). Il vérifie sous le
verrou exclusif que la décision est toujours courante et échue, ajoute une ligne
`expire` d'auteur `system`, recalcule et journalise (`triage.expired`) ; il est
idempotent, et remet en file une échéance pas encore atteinte (horloges décalées). Le
retour « à analyser » a donc lieu le jour même.

### Droits

- `finding.triage` (déjà dans la matrice, ADR 0034) : décider pour un projet, importer un
  VEX pour lui, retirer une décision du projet — rôle d'équipe analyste ou
  administrateur.
- Nouvelle permission d'organisation **`triage.org`**, réservée aux administrateurs de
  l'organisation : décider pour toute l'organisation, importer un VEX d'organisation,
  retirer une décision d'organisation, voir la liste des décisions d'organisation. Une
  décision d'organisation touche les projets de toutes les équipes, et sa liste révèle
  des composants de projets qu'un membre ne voit pas.
- Chaque décision est journalisée (`triage.decided`, `triage.withdrawn`,
  `triage.expired`) ; un import l'est une fois avec ses décomptes
  (`triage.vex_imported`), ses décisions portant l'auteur `vex:<source>` et le compte qui
  a importé.

## Conséquences

- Aucune réinjection dans Grype : même effet pour l'utilisateur (un constat non affecté
  ne remonte plus dans les listes ni dans les indicateurs), sans état caché dans la base
  de vulnérabilités, et une décision s'applique aussi aux constats futurs.
- Le tableau de bord ne compte plus les constats « non affecté » ni « faux positif »
  parmi les constats ouverts ; « risque accepté », « affecté », « corrigé » (en attente
  de confirmation par un instantané) et « à analyser » comptent toujours.
- L'effet sur la sécurité d'une comparaison d'instantanés (T17, ADR 0038) ignore les
  constats « non affecté » et « faux positif ».
- Un constat résolu garde son statut effectif, recalculé comme les autres ; rouvert, il
  le retrouve.
- La table `triage_decisions` croît sans purge ; elle ne contient que des décisions
  humaines, des imports bornés (5 000 déclarations) et une ligne par échéance.

## Alternatives écartées

- **Réinjecter les décisions dans Grype** (VEX passé à la correspondance) : l'adaptateur
  cesserait d'être pur, une décision ne vaudrait qu'aux analyses suivantes, et Grype
  ignore la portée projet ou organisation de lotor.
- **Calcul du statut effectif à la lecture** (jointure latérale vers les décisions) :
  impossible en SQL pour une plage `vers`, et chaque écran, filtre et agrégat aurait
  répété le calcul ; une jointure par constat sur un million de liens pèse sur les
  recherches et le tableau de bord.
- **Décisions modifiables en place** : l'historique complet et l'audit exigent l'ajout
  seul ; un retrait explicite rend le même service qu'une suppression.
- **Échéance par balayage horaire de toutes les organisations** : un job par
  organisation et par heure pour une poignée de décisions ; le job par décision part à
  l'heure exacte.
- **Laisser un analyste d'équipe décider pour toute l'organisation** : il modifierait le
  statut de constats d'équipes qu'il ne voit pas.
