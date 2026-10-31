# 0030 — Durcissement de la base et bornes de ressources : journal en ajout seul, rôle sans DDL, quotas d'ingestion, plafonds par compte

- Statut : Accepté
- Date : 2026-10-31
- Lot : T11

## Contexte

La revue de sécurité du lot 1 (T11) a relevé :

- **SEC-04** (Low) : le rôle d'exécution pouvait `UPDATE` et `DELETE` les journaux d'audit
  (privilèges par défaut de 001) ; le modèle de menace les annonce « non modifiables par
  l'application », et `RescueTOTP` décide « ticket déjà appliqué » en lisant ce journal.
- **SEC-12** (Note) : `CheckRuntimeRole` ne contrôlait pas le droit `CREATE` (base,
  schéma `public`) ; un objet du rôle d'exécution échapperait à la RLS, et `public` est
  dans le `search_path` des fonctions `SECURITY DEFINER`.
- **SEC-05** (Low) : aucun quota de stockage ; un jeton d'agent volé écrivait environ
  3,8 Gio par minute dans le PostgreSQL commun à toutes les organisations.
- **SEC-06** (Low) : le réencodage d'un SBOM téléchargé (plusieurs centaines de Mio en
  mémoire) était synchrone et sans borne de concurrence, ouvert au rôle `viewer`.
- **SEC-07** (Low) : les 4 places d'export de l'instance étaient monopolisables par un seul
  compte qui lit lentement.
- **SEC-11** (Note) : `ingest.decode_timeout` n'annulait que les étapes en base.

## Décision

- **Journal d'audit en ajout seul** : la migration 015 retire `UPDATE`, `DELETE` et
  `TRUNCATE` sur `audit_events` et `instance_audit_events` au rôle d'exécution. La RLS
  reste (lecture et ajout limités à l'organisation). Les actions des clés étrangères
  s'exécutent avec les droits du propriétaire. Une rétention future passera par une
  fonction `SECURITY DEFINER` dédiée, bornée en âge.
- **Rôle d'exécution sans DDL** : la migration 015 retire `CREATE` sur `public` à
  `PUBLIC` ; `CheckRuntimeRole` refuse au démarrage un rôle qui a `CREATE` sur la base ou
  sur `public`, ou `UPDATE`, `DELETE`, `TRUNCATE` sur un journal d'audit.
- **Quotas d'ingestion** (configurables, 0 pour aucun) : `ingest.max_per_ref_per_day`
  (200 envois stockés par référence sur 24 h glissantes, doublons non comptés) et
  `ingest.max_org_storage_mib` (10 Gio compressés par organisation). Au-delà : 429
  `error.ingest.quota` avec `Retry-After`, transaction annulée (rien n'est stocké). Index
  partiel `ingestions_ref_received_idx`. La rétention reste à T17.
- **Plafonds par compte** : un export de recherche à la fois par compte
  (`search.MaxExportsPerAccount`), en plus du plafond de l'instance ; les réencodages de
  SBOM prennent une place parmi `ingest.max_reencodes` (2) de l'instance, une par compte,
  429 sinon. Un client parti avant le réencodage ne l'engage pas.
- **Délai du décodage** : la lecture en flux de `Precheck` s'interrompt au délai et le
  contexte est vérifié entre les étapes ; un dépassement rend l'erreur du contexte (job
  réessayé), jamais un refus. Validation par schéma et décodage de Syft, sans contexte et
  linéaires en taille, vont au bout de l'étape commencée : c'est documenté, pas caché.

## Conséquences

- La procédure de changement de rôle d'exécution (`docs/operations.md`) doit retirer les
  droits de modification du journal après le `GRANT … ON ALL TABLES`, sinon le serveur
  refuse de démarrer.
- Les quotas peuvent refuser un dépôt très actif (plus de 200 commits analysés par jour
  sur une branche) : l'exploitant relève `ingest.max_per_ref_per_day`. Le compte du
  volume est approché : deux envois simultanés peuvent dépasser la borne d'un envoi.
- Le volume d'une organisation se calcule par une somme sur ses blobs à chaque envoi
  (table sans contenu en ligne, `STORAGE EXTERNAL`) ; à surveiller si une organisation
  dépasse des centaines de milliers de blobs (T17 réduira ce nombre).
- Il faut plusieurs comptes pour monopoliser exports et réencodages ; les comptes sont
  créés par les administrateurs d'instance.

## Alternatives écartées

- **Abandonner le décodage dans une goroutine** au délai : le calcul continuerait sans
  propriétaire (mémoire et CPU), contraire au § 22 ; le gain est faible tant que le coût
  reste linéaire et borné par le plafond par organisation.
- **Précalculer les formats dérivés dans un job** : stockage triplé pour un usage rare ; à
  reconsidérer si les téléchargements réencodés deviennent fréquents.
- **Couper un export trop lent (débit minimal)** : complexe à régler sans faux positifs ; le
  plafond par compte suffit à empêcher la monopolisation par un seul compte.
- **Quota par jeton d'agent** plutôt que par référence : un agent serveur n'a qu'une
  référence, un agent dépôt beaucoup ; la référence est l'unité qui grossit l'historique.
