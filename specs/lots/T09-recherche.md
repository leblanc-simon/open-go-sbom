# T09 — Recherche transverse

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T06 | Terminé |

## Objectif

Répondre en moins de 2 s à « qui utilise ce composant, cette version, cette plage de
versions ? » et « qui est touché par cette CVE ? », à l'écran comme par l'API.

## Périmètre

**Inclus**

- `internal/version` : comparaison par écosystème (npm, Maven, PEP 440, RubyGems, Go,
  Debian, RPM, Alpine, semver générique) via l'adaptateur `grypeversion`, et analyseur de
  plages `vers` maison.
- `internal/search` : détection du type de requête (§ 13), filtres, plan d'exécution,
  pagination par projet, export CSV et JSON en flux.
- Index : extension `pg_trgm` et index trigramme sur le nom, index sur
  (`org_id`, `purl_base`), sur les composants des ensembles d'inventaire, sur `ref_current`
  et sur `findings` par vulnérabilité. Tous commencent par `org_id`, car la RLS évalue son
  filtre avant les opérateurs non `LEAKPROOF` comme les trigrammes (§ 13 de l'architecture) ;
  GIN composite via `btree_gin` si la mesure l'exige.
- Écran de recherche : barre unique, rappel du type détecté, filtres en formulaire `GET`,
  résultats groupés par projet, boutons d'export.
- Jetons d'accès personnels (`ogsbom_pat_`) : création et révocation depuis le profil, lecture
  seule, limités aux organisations du compte ; route `GET /api/v1/orgs/{org}/search`.
- Banc d'essai `make bench-search` sur le jeu de données synthétique de T06.

**Exclu** : recherche à une date passée (T21), recherche par licence enrichie par Grant (T20).

## Conception

- Une plage `vers` n'est acceptée qu'avec un `purl_base` exact : le SQL réduit l'ensemble à
  ce paquet dans l'organisation (un nombre borné de versions), puis Go filtre les versions
  avec le comparateur de l'écosystème et pagine. Une plage n'est jamais comparée comme du
  texte, et une recherche approchée par nom refuse une plage avec un message explicite.
- Une version non comparable dans son écosystème est signalée dans le résultat plutôt
  qu'ignorée en silence.
- L'export lit en flux et écrit en flux : mémoire constante quel que soit le volume.
- La création de l'extension `pg_trgm` est documentée pour les bases gérées.

## Livrables

Paquets, migrations, écran, route d'API, jetons personnels, banc d'essai, section
« Recherche » de la documentation utilisateur.

## Maquettes

Planches « 1 · Recherche transverse » et sa variante en thème sombre du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] `vers:npm/<4.17.21` sur `pkg:npm/lodash` ne renvoie que les versions inférieures.
- [x] `CVE-2021-44228` renvoie les projets touchés avec statut et version corrigée.
- [x] Le SHA-256 d'un fichier connu d'un SBOM d'exemple renvoie le composant et ses projets.
- [x] Les filtres sont reflétés dans l'URL ; une URL partagée redonne le même résultat.
- [x] L'API renvoie exactement les mêmes résultats que l'écran.
- [x] Banc d'essai : moins de 2 s au 95e centile sur 1 000 projets et 1 million de liens,
      **RLS active** et avec le rôle d'exécution réel, selon `docs/benchmarks.md` (mesure
      et plans d'exécution consignés).
- [x] Les plans des requêtes de recherche utilisent les index prévus malgré la RLS (vérifié
      par `EXPLAIN` dans un test).
- [x] Un jeton personnel révoqué est refusé ; il ne donne jamais plus de droits que son
      propriétaire.

## Tests attendus

Fuzzing de l'analyseur de requête et de `vers`. Tables de comparaison de versions par
écosystème. Intégration sur un petit jeu connu ; isolement entre organisations.

## Points à trancher

Aucun.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T09-recherche`.

### Livré

- **`internal/version`** (ADR 0026) : règles de comparaison (npm, Maven, PEP 440,
  RubyGems, Go, Debian, RPM, Alpine, semver générique), règle d'un type de purl,
  interface `Comparer`, tri (`Sort`, versions illisibles à part), analyseur de plages
  `vers` maison (`ParseVers` : forme, schéma, lisibilité et unicité des versions, tri ;
  `Range.Contains` : algorithme de la spécification ; `String` : forme normale).
  **`version/grypeversion`** : implémentation par les comparateurs de Grype, rendus
  antisymétriques et avec l'époque rpm absente valant 0.
- **`internal/token`** : format des jetons (`agt`, `enr`, `pat`) sorti d'`internal/agent`,
  qui garde son API par alias.
- **Migration 013** : extensions `pg_trgm` et `btree_gin` ; index GIN
  `(org_id, name gin_trgm_ops)`, `(org_id, hashes)`, B-tree `(org_id, lower(name))` ;
  fonctions `ogsbom_search_component_names` et `ogsbom_search_component_hashes` ; table
  globale `personal_access_tokens`. `internal/db/crossorg` : `ComponentsByName`,
  `ComponentsByHash`.
- **`internal/search`** : détection du type de requête (nom, purl et plage, CVE/GHSA,
  SHA-256 ; `license:` refusé jusqu'à T20), `Request` en paramètres d'URL (filtres type de
  projet, étiquette, origine, KEV, sévérité maximale, constats résolus ; ordre risque, nom,
  instantané), exécution sous la RLS, pagination par projet, occurrences par projet (100),
  occurrences hors plage et versions illisibles signalées, export CSV et JSON en flux
  (`ExportLimiter`), étiquettes de l'organisation pour les filtres.
- **Jetons d'accès personnels** (ADR 0025) : `account.CreatePersonalToken`,
  `PersonalTokens`, `RevokePersonalToken`, `AuthenticateToken` ; actions d'audit
  `personal_token.created` et `personal_token.revoked`.
- **API utilisateur** : `GET /api/v1/orgs/{org}/search` et `/search/export` (tag `user`
  d'`api/openapi.yaml`, serveur généré dans `internal/api/gen/userapi`), jeton personnel,
  limitation par jeton, refus limités par IP, garde d'organisation, mêmes paramètres et
  mêmes résultats que l'écran (`api.MountUser`, `api.ServeExport`, `api.SearchResult`).
- **Configuration** : fragment `user_api` (`rate_limit` 60, `failure_rate_limit` 30,
  `export_timeout` 5 min, `max_exports` 4).
- **Écrans** (fr, en, clair, sombre ; planche « 1 · Recherche transverse ») : recherche
  `/o/{slug}/search` (barre, « Interprété comme », aide de syntaxe, filtres en formulaire
  GET, filtres actifs retirables, résultats groupés par projet, export, page suivante),
  entrée « Recherche » de la navigation d'organisation, page « Jetons d'accès » du profil.
  Fiche composant : versions triées selon l'écosystème (`version.Sort`). Composants CSS
  `chip--filter`, `chip__remove` ; écran `screens/search.css` (`search`, `qtoken`,
  `syntax-list`, `search-layout`, `facets`, `result-group`, `toolbar`).
- **Banc d'essai** : `make bench-search` (`TestSearchBenchmark`), compléments du jeu
  `benchdata.AddSearchFixtures` ; `TestSearchPlansUseTheirIndexes` à chaque CI.
- **Docs** : ADR 0024, 0025, 0026 (tableau de l'ADR 0012 complété) ; `architecture.md`
  (§ 3, 6, 8, 9, 10, 13, 14, 15) ; `docs/utilisation.md` (nouveau guide d'utilisation,
  section « Recherche ») ; `docs/operations.md` (« Recherche et API utilisateur ») ;
  `docs/benchmarks.md` ; modèle de menace ; `config.example.yaml`.

### Tests

- Unitaires : tables de comparaison par écosystème (règles nommées, cas faux en ordre
  lexical), versions illisibles, plages vers (appartenance, refus, forme normale, jamais
  textuelle), détection du type de requête et refus traduisibles, aller-retour des filtres
  par l'URL, filtres inconnus refusés, cellules CSV neutralisées. Fuzzing :
  `FuzzCompare`, `FuzzParseVers`, `FuzzParse`, `FuzzParseRequest` (une minute chacun en
  local ; une non-antisymétrie de PEP 440 trouvée et gardée en corpus).
- Intégration (petit jeu connu analysé par une fausse base) : plage sur lodash, purl avec
  version, CVE et GHSA (statut, versions corrigées triées), empreinte du SBOM
  `portail-client-ia` (composant trouvé par l'IA), nom, faute de frappe, filtres,
  pagination dans les trois ordres, curseur d'un autre ordre refusé, constats résolus,
  export CSV et JSON, isolement entre organisations, projets archivés et références
  retirées exclus ; fonctions de recherche dans l'organisation déclarée seulement et en
  échec hors `InOrg` ; jetons personnels (secret jamais stocké ni journalisé, révocation,
  expiration, compte désactivé, borne, audit) ; écran (deux langues, accessibilité, aucun
  code en ligne, URL partagée = même page), API = écran, organisation étrangère 404,
  membre retiré refusé à la requête suivante, jeton révoqué 401 ; plans d'exécution.
- Harnais d'isolement par route : `/o/{slug}/search` et `/search/export` couverts ;
  routes globales `/account/tokens…` ajoutées à la liste.

### Décisions

- **ADR 0024** **[à relire]** : deux fonctions `SECURITY DEFINER` « équivalentes à la RLS »
  pour la recherche par nom et par empreinte (organisation lue dans `ogsbom.org_id`,
  jamais en paramètre), car aucun opérateur trigramme ou de tableau n'est `LEAKPROOF` ;
  nom = sous-chaîne sans casse, puis ressemblance par trigrammes si rien ne contient la
  requête, nom exact sous trois caractères ; bornes 1 000 composants par nom ou empreinte,
  5 000 par paquet, 20 projets par page (100 au plus), 100 occurrences par projet ; export
  en flux dans une transaction en lecture, borné en nombre simultané et en durée.
- **Nouvelles fonctions `crossorg`** (changement de sécurité, à relire) :
  `ogsbom_search_component_names(query, limit)` et
  `ogsbom_search_component_hashes(hash, limit)`. Elles contournent la RLS (propriétaire
  `BYPASSRLS`) uniquement pour que les index GIN servent ; elles appliquent la même
  condition que la politique standard, lisent l'organisation dans `ogsbom.org_id` (donc
  seulement dans `InOrg`, échec franc sinon), ne renvoient que des identifiants de
  composants de cette organisation, bornés à 1 001 ; aucun texte de requête n'est
  interprété (jokers `ILIKE` échappés). Test : `TestSearchFunctionsStayInTheDeclaredOrganization`.
- **ADR 0025** **[à relire]** : jetons personnels dans une **table globale** (donnée du
  compte), écart au § 8 qui les rangeait parmi les tables d'organisation ; valables en
  lecture sur les organisations dont le compte est membre au moment de chaque requête ;
  expiration obligatoire (7 à 365 jours, 90 par défaut) ; 20 actifs au plus ; aucune
  nouvelle fonction `crossorg` (garde par `crossorg.Access`) ; pas encore de session dans
  l'API utilisateur.
- **ADR 0026** **[à relire]** : comparateurs de Grype rendus antisymétriques ; époque rpm
  absente = 0 ; schéma vers égal à la règle du purl (`vers:semver` refusé sur `pkg:npm`) ;
  types de purl inconnus comparés en semver générique.
- Purl avec version : version comparée **comme texte exact** (forme canonique), quels que
  soient les qualificatifs ; qualificatifs et sous-chemin donnés restreignent. Une plage
  s'applique à la version lue dans le purl canonique du composant **[à relire]**.
- Recherche par vulnérabilité : constats ouverts, résolus seulement sur demande
  (`resolved=1`) ; occurrence = constat ; « origine » = élément de l'inventaire courant
  (vide si le composant l'a quitté) **[à relire]**.
- Valeurs par défaut **[à relire]** : 60 requêtes par minute et par jeton personnel,
  30 refus par minute et par IP, 4 exports simultanés par instance, 5 min par export.
- Filtres : valeurs d'un même filtre en « ou », filtres entre eux en « et » ; une valeur
  inconnue dans l'URL est refusée (400) plutôt qu'ignorée.
- Export : en-têtes CSV et clés JSON en identifiants anglais stables (format de données,
  pas texte d'interface).
- L'API utilisateur est montée opération par opération dans le sous-routeur
  `/api/v1/orgs/{org}` (la chaîne CORS doit précéder le routage), par l'adaptateur généré.

### Écarts

- **Maquette** : pas de compteurs par valeur de filtre (un agrégat par filtre sur des
  dizaines de milliers d'occurrences, pour une information secondaire), pas de
  regroupement par composant ou par vulnérabilité (la fiche demande « groupés par
  projet »), pas de colonne « Emplacement » (les chemins de fichier ne sont pas stockés),
  pas de filtre d'équipe (T16) ni de recherche à une date passée (T21).
- `license:` reconnu mais refusé avec un message explicite : la recherche par licence est
  portée par T20 (critère `license:AGPL-3.0-only`).
- Index de la fiche sur `(org_id, purl_base)`, les éléments d'ensemble, `ref_current` et
  `findings` par vulnérabilité : déjà créés en T05 et T06, vérifiés par `EXPLAIN`, non
  dupliqués.
- Pas de session avec en-tête CSRF dans l'API utilisateur (§ 14) : aucun écran ne l'appelle
  en JavaScript ; l'écran sert ses propres exports.
- Mesures dans l'environnement de réalisation (4 cœurs, 15 Gio), pas sur la machine de
  référence : la cible tient avec une marge d'un facteur cinq **[à relire]**.

### ADR créés

0024, 0025, 0026 (et tableau de l'ADR 0012 complété).

### Mesures

- Banc d'essai (jeu de référence, rôle d'exécution, RLS active, 50 passages chauds) :
  p95 de 17 ms (purl d'un paquet) à **348 ms** (nom large, 16 675 occurrences dans 1 000
  projets) ; plage vers sur lodash 39 ms ; vulnérabilité 36 ms ; empreinte 128 ms ; export
  CSV de 16 675 lignes p95 0,94 s. Détail et plans dans `docs/benchmarks.md`.
- Couverture (unitaires et intégration) : `search` 88,4 %, `version` 97,5 %,
  `version/grypeversion` 90,9 %, `token` 96,4 %, `account` 85,4 %, `db/crossorg` 81,8 %,
  `benchdata` 85,7 %, `web` 81,6 %, `config` 97,7 %.

### Pour les lots suivants

- **T10 (tableau de bord)** : « composants vulnérables les plus répandus » peut s'appuyer
  sur les mêmes jointures que `search` (`component_set_items` → `ref_current`) ; l'entrée
  « Recherche » a été ajoutée en tête de `orgNav` (après « Vue d'ensemble »).
- **T11 (recette)** : vérifier `make bench-search` sur la machine de référence ; relire
  les deux fonctions de recherche comme du code de sécurité ; audit d'accessibilité de
  l'écran.
- **T16 (équipes)** : filtre d'équipe à ajouter dans `search.hitsSQL` (et la facette) ;
  les jetons personnels suivent les droits du compte, donc ses équipes.
- **T20 (licences)** : brancher `license:` dans `search.Parse` (aujourd'hui
  `KeyLicense`), index sur les licences des éléments d'ensemble par une fonction du même
  type que la recherche par nom si `@>` sur un tableau est nécessaire.
- **T21 (date passée)** : remplacer `ref_current` par l'instantané en vigueur à la date
  dans `componentHits` ; la `Request` porte déjà ses paramètres d'URL.
- Toute nouvelle route de l'API utilisateur : opération du tag `user`, montée dans
  `api.MountUser` par l'adaptateur `userapi.ServerInterfaceWrapper`.
