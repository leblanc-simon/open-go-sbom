# 0024 — Recherche transverse : index sous la RLS, plan d'exécution, pagination et export

- Statut : Accepté
- Date : 2026-10-31
- Lot : T09

## Contexte

T09 répond à « qui utilise ce composant, cette version, cette plage de versions ? » et
« qui est touché par cette CVE ? » en moins de 2 s au 95e centile sur 1 000 projets et
1 million de liens, RLS active (§ 13 de l'architecture). Trois difficultés :

- **La RLS empêche l'usage des index de recherche.** PostgreSQL évalue la condition d'une
  politique avant tout opérateur non `LEAKPROOF`, et un tel opérateur ne peut pas servir de
  condition d'index (`restriction_is_securely_promotable`). `ILIKE`, `%` (trigrammes) et
  `@>` (tableaux) ne sont pas `LEAKPROOF` : vérifié dans `pg_proc`, et par `EXPLAIN` sous
  le rôle d'exécution, un `name ILIKE '%…%'` lit tous les composants de l'organisation
  (70 ms pour 60 000 composants, linéaire), même avec un index GIN composite qui commence
  par `org_id`. Seul un superutilisateur peut marquer une fonction `LEAKPROOF`, ce qu'une
  base gérée n'accorde pas au propriétaire. L'égalité de texte et d'uuid, et `= ANY`, sont
  `LEAKPROOF` : les index B-tree restent utilisables.
- **Une plage `vers` ne se compare pas en SQL** : l'ordre des versions dépend de
  l'écosystème (ADR 0026).
- **Pagination par projet et export** sur des résultats potentiellement gros (une
  recherche large touche des dizaines de milliers d'occurrences).

## Décision

- **Deux fonctions `SECURITY DEFINER` « équivalentes à la RLS »** (migration 013) :
  `ogsbom_search_component_names(query, limit)` et
  `ogsbom_search_component_hashes(hash, limit)`, du propriétaire (`BYPASSRLS`), à
  `search_path` fixé. Elles **lisent l'organisation dans `ogsbom.org_id`** (posé par
  `InOrg`), jamais en paramètre, et appliquent elles-mêmes la condition de la politique
  standard : même périmètre que la RLS, même échec franc hors `InOrg` (`''::uuid`). Elles
  ne renvoient que des identifiants de composants (et l'indication « approché »), bornés à
  1 001. Ce ne sont pas des lectures inter-organisations, mais elles contournent la RLS :
  elles vivent dans `internal/db/crossorg` (`ComponentsByName`, `ComponentsByHash`, qui
  exigent une `*db.OrgTx`) et s'ajoutent au tableau de l'ADR 0012 comme changement de
  sécurité.
- **Nom** : sous-chaîne sans casse (`ILIKE`, jokers échappés), nom exact puis ressemblance
  décroissante ; si aucun nom ne contient la requête, ressemblance par trigrammes (`%`,
  faute de frappe), signalée comme approchée ; moins de trois caractères : nom exact.
  Bornes : 1 000 composants (résultat marqué tronqué au-delà).
- **Index** : GIN composites (`btree_gin`) `(org_id, name gin_trgm_ops)` et
  `(org_id, hashes)`, B-tree `(org_id, lower(name))`. Ceux que demandait la fiche sur
  `(org_id, purl_base)`, les éléments d'ensemble, `ref_current` et `findings` par
  vulnérabilité existaient depuis T05 et T06 ; `EXPLAIN` montre qu'ils suffisent.
- **Plan** (une transaction `InOrg` en lecture seule) : la requête désigne des composants
  (nom et empreinte par les fonctions ci-dessus ; purl par `purl_base` sous la RLS,
  5 000 composants au plus, puis version, qualificatifs, sous-chemin et plage filtrés en
  Go) ou des vulnérabilités (identifiant et alias du catalogue, global) ; les occurrences
  sont lues sur `component_set_items` → `ref_current` → références et projets actifs, avec
  la pire vulnérabilité ouverte (`findings`), filtres en SQL ; une recherche par
  vulnérabilité lit `findings` (ouverts, et résolus sur demande).
- **Pagination par projet** : agrégat par projet (nombre, risque maximal, instantané le plus
  récent) et totaux par fonctions de fenêtre, curseur par clé (risque, nom ou date, puis nom
  et identifiant), 20 projets par page (100 au plus), puis les occurrences des projets de
  la page (100 par projet, l'export les donne toutes). Les occurrences hors de la plage et
  les versions illisibles sont comptées avec les mêmes filtres.
- **Export en flux** : une requête ordonnée, lue ligne à ligne et écrite ligne à ligne
  (CSV avec cellules « formules » neutralisées, JSON écrit élément par élément) ; mémoire
  constante. La lecture tient une transaction en lecture seule pendant l'écriture : les
  exports sont **bornés par instance** (`user_api.max_exports`, 4 ; 429 au-delà) et **en
  durée** (`user_api.export_timeout`, 5 min, délai d'écriture HTTP prolongé d'autant).
- Même `search.Request` (paramètres d'URL) pour l'écran et l'API : une URL partagée redonne
  le même résultat, et l'API répond exactement comme l'écran.
- `license:` est reconnu et refusé avec un message explicite jusqu'à T20.

## Conséquences

- Mesures (jeu de référence, `make bench-search`, `docs/benchmarks.md`) : p95 de 17 ms
  (purl) à 348 ms (nom large, 16 675 occurrences), export CSV de 16 675 lignes en 0,94 s.
- La recherche par nom ou empreinte dépend de deux fonctions à relire comme du code de
  sécurité : toute modification garde la condition `org_id = current_setting(…)::uuid`, un
  test vérifie qu'elles ne sortent pas de l'organisation déclarée et échouent hors `InOrg`.
- Le GIN composite lit toute la liste de l'organisation pour sa clé `org_id` : une
  empreinte précise coûte une centaine de millisecondes sur 60 000 composants, et le
  planificateur lui préfère la clé primaire sur une petite organisation. Un index GIN
  simple (sans `org_id`) serait plus rapide pour une seule organisation, mais lirait les
  correspondances de toutes les organisations ; à revoir sur mesure d'une instance réelle
  à nombreuses organisations.
- Un export garde une connexion du pool pendant son écriture : `max_exports` se règle
  avec `database.max_open_conns`.
- Les extensions `pg_trgm` et `btree_gin` (« trusted ») sont créées par le propriétaire de
  la base ; une base gérée qui les réserve à un administrateur les crée avant la
  migration (`docs/operations.md`).

## Alternatives écartées

- **Opérateurs non `LEAKPROOF` sous la RLS** : aucun index, coût linéaire en composants de
  l'organisation ; ne tient pas l'exigence « index prévus utilisés malgré la RLS ».
- **Marquer des fonctions `LEAKPROOF`** : réservé au superutilisateur.
- **Table globale des noms ou des empreintes** : donnée d'organisation hors RLS
  (principe 6).
- **Organisation en paramètre des fonctions** : une erreur d'appel lirait une autre
  organisation ; la lire dans `ogsbom.org_id` donne exactement la garantie de la RLS.
- **Table dérivée `component_hashes` (B-tree sur l'égalité)** : utilisable sous la RLS,
  mais une table et une écriture de plus à chaque ingestion, pour une seule recherche.
- **Export paginé en plusieurs transactions courtes** : mémoire bornée par lot, mais un
  agrégat complet par lot (coût quadratique) ou des lots non bornés par projet.
- **Comparer les versions en SQL** (tri lexical, ou `string_to_array`) : faux pour la
  plupart des écosystèmes (ADR 0026).
