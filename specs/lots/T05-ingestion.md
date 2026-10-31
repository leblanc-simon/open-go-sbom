# T05 — Ingestion des SBOM et inventaire

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T02, T04 | Terminé |

## Objectif

Recevoir un SBOM d'agent, le borner, le décoder, le normaliser et le ranger en instantané
d'une référence suivie, avec des ensembles d'inventaire adressés par contenu.

## Périmètre

**Inclus**

- `internal/sbom` : modèle interne (`Document`, `Component` : purl, nom, version, type, CPE,
  licences, empreintes, origine, confiance, preuve, portée), canonicalisation des purl,
  calcul de `purl_base`, **empreinte d'inventaire** indépendante des horodatages et numéros
  de série du document.
- `internal/sbom/syft` : détection du format, décodage de CycloneDX JSON 1.5 à 1.7, SPDX
  JSON 2.3, Syft JSON ; lecture des propriétés `lotor:` et du champ `evidence` ; encodage
  CycloneDX 1.6 et SPDX 2.3 pour l'export.
- `internal/ingest` : route `POST /api/v1/agent/ingestions` (multipart du § 11), contrôles
  synchrones, stockage du blob compressé et dédoublonné, job `ingest.decode` mis en file
  dans la même transaction, route `GET /api/v1/agent/ingestions/{id}`.
- Bornes préalables par lecture en flux (taille décompressée, profondeur JSON, nombre de
  composants) avant tout décodage complet.
- `internal/inventory` : upsert trié des composants de l'organisation, ensembles
  d'inventaire (réutilisés si l'empreinte existe), instantanés selon la règle du § 11,
  `ref_current`, puis mise en file de `analysis.ref` si l'ensemble courant a changé
  (handler livré en T06).
- Extension de `GET /api/v1/agent/projects` (T04) : commit du dernier instantané de chaque
  référence, utilisé par l'agent dépôt pour son rattrapage.
- Écrans : onglet « Instantanés » de la fiche projet (date, commit, agent, nombre de
  composants par origine) ; détail d'un instantané avec la liste filtrable des composants ;
  téléchargement du SBOM d'un instantané (original, ou réencodé en CycloneDX 1.6 ou SPDX 2.3).

**Exclu** : correspondance des vulnérabilités (T06), différences entre instantanés et
rétention (T17).

## Conception

- Canonicalisation : encodage, casse et tri des qualificatifs selon la spécification purl ;
  règles de nom propres à chaque type (npm, PyPI, Go…). **Aucun qualificatif d'identité
  n'est retiré** (`distro`, `arch`, `epoch`, `upstream`…). Un composant sans purl reçoit un
  purl `generic` et est signalé.
- Insertion par lots via `unnest` de tableaux typés, clés triées pour éviter les
  interblocages entre ingestions concurrentes de la même organisation.
- Règle d'instantané : un instantané par (référence, commit) pour un dépôt, même à
  inventaire identique ; pour un hôte, un inventaire identique au courant ne fait que mettre
  à jour la date de dernière analyse.
- Le décodage tourne dans le job, jamais dans la requête HTTP. ADR : décodage dans le
  processus worker (avec bornes préalables et plafond par organisation) ou dans un
  sous-processus limité en temps et en mémoire.
- Ré-ingérer le même SBOM pour la même référence et le même commit ne crée rien (idempotence).

## Livrables

Paquets ci-dessus, migrations, description OpenAPI, SBOM d'exemple dans `testdata/sbom/`
(dont des hôtes Debian, RHEL et Alpine) et fichiers attendus, écrans, ADR du décodage.

## Maquettes

Planches « 4a · Fiche projet — dépôt » (onglet des instantanés) du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Chaque format d'exemple produit le `Document` attendu (fichiers « golden »), avec
      qualificatifs `distro`, `arch` et `epoch` et CPE conservés.
- [x] Un SBOM malformé, trop gros, trop profond ou trop riche produit une ingestion
      `failed` avec une clé d'erreur, sans instantané partiel, avant tout décodage complet.
- [x] Deux SBOM qui ne diffèrent que par l'horodatage et le numéro de série ont la même
      empreinte d'inventaire.
- [x] Deux commits successifs d'un dépôt sans changement de dépendances : deux instantanés,
      un seul ensemble d'inventaire.
- [x] Deux envois identiques d'un hôte : un seul instantané, date de dernière analyse mise
      à jour.
- [x] Un même purl dans deux organisations donne deux lignes `components` distinctes.
- [x] Un agent ne peut pas envoyer pour une référence qui ne lui est pas confiée.
- [x] Le SBOM téléchargé en CycloneDX et en SPDX est valide pour son format.
- [x] Ingestion de 5 000 composants : durée mesurée et consignée dans le Journal.

## Tests attendus

Fuzzing de la canonicalisation des purl, des bornes préalables et du décodage. Intégration
de bout en bout (envoi → job → instantané), y compris ingestions concurrentes. Tests
d'isolement sur les routes et les écrans.

## Décisions

Prises le 31 octobre 2026 :

- Composant sans purl : gardé sous `pkg:generic/<nom>@<version>` et marqué
  « identification faible ».
- Validation par les schémas JSON officiels de CycloneDX et SPDX, embarqués, avec
  `github.com/santhosh-tekuri/jsonschema` (validé).

## Journal

Réalisé le 31 octobre 2026, branche `lot/T05-ingestion`.

### Livré

- **Dépendances** (validées au § 5) : `github.com/anchore/syft` v1.55.0 (premier import
  direct), `github.com/package-url/packageurl-go` v0.1.7,
  `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3, `github.com/CycloneDX/cyclonedx-go`
  v0.12.0 (import direct dans `sbom/syft` pour le réencodage). La directive `go` passe de
  1.26.3 à 1.26.8, minimum exigé par Syft v1.55.0 (la chaîne reste 1.26.10). govulncheck :
  aucune vulnérabilité atteinte.
- `internal/sbom` : `Document`, `Component` (purl canonique, `purl_base`, type, nom,
  version, CPE, licences, empreintes, origine, confiance, modèle, preuve, portée,
  identification faible), `CanonicalPURL`, `GenericPURL`, `ComponentPURL`, `Normalize`
  (bornes de champs, fusion des doublons indépendante de l'ordre), `Fingerprint`
  (empreinte d'inventaire versionnée), `Precheck` (analyseur JSON en flux : objet bien
  formé, taille, profondeur, composants, format et version), clés d'erreur `error.ingest.*`.
- `internal/sbom/schema` : schémas officiels embarqués de CycloneDX 1.5, 1.6, 1.7 et SPDX
  2.3 (sources, étiquettes, SHA-256 et licences dans `schemas/README.md`), compilés une
  fois, sans réseau ; `Validate` (réception) et `ValidateStrict` (production),
  `CycloneDXLicenseIDs`.
- `internal/sbom/syft` : `Decode` (décodeurs de Syft, relecture CycloneDX pour empreintes,
  portée, propriétés `lotor:` et `evidence`, sommes de contrôle SPDX, exclusion du
  composant décrit, paniques converties en refus), `Encode` (CycloneDX 1.6 par
  `cyclonedxhelpers` + cyclonedx-go, licences trop récentes écrites en nom ; SPDX 2.3).
- Migration **008** : `jobs.org_id` → `organizations` (`ON DELETE CASCADE`) ;
  `sbom_blobs`, `components`, `component_sets`, `component_set_items`, `snapshots`,
  `ref_current`, `ingestions`, RLS standard, clés composites (référence + projet,
  instantané + ensemble avec `ON UPDATE CASCADE`, agent en `ON DELETE SET NULL (agent_id)`).
  Harnais d'isolement SQL étendu ; tests de `internal/jobs` sur de vraies organisations.
- `internal/inventory` : `Store` (référence verrouillée, upsert trié par lots `unnest`,
  ensemble réutilisé ou créé avec ses éléments, règle dépôt/hôte, `ref_current`,
  `analysis.ref` en file si l'ensemble courant change), lectures (`ListSnapshots`,
  `GetSnapshot`, `RefStates`, `CurrentByRef`, `LastSnapshotByProject`, `ListItems`,
  `ItemTypes`) et `Service` pour les écrans ; constantes `AnalysisKind`,
  `AnalysisPayload`, `AnalysisUniqueKey` pour T06.
- `internal/ingest` : `Authorize`, `Receive` (lecture bornée, empreinte, blob gzip
  dédoublonné, ingestion et job dans la même transaction, doublon de dépôt, refus stockés
  en `failed`), `DecodeHandler`/`Decode` (idempotent, testé deux fois), `Get`, `Recent`,
  `Blob`, `Export`.
- API (`api/openapi.yaml`, code régénéré) : `createIngestion` (multipart `context` puis
  `sbom`, 202/200/400/401/404/413/429), `getIngestion`, `TrackedRef.last_snapshot` dans
  `listAgentProjects` ; `operationKinds` complété ; corps de toute requête d'agent borné
  (`limitBody` remplace `limitJSON`) ; erreurs d'ingestion traduites dans la réponse.
- Configuration : fragment `ingest` (`max_upload_mib` 32, `max_decompressed_mib` 64,
  `max_depth` 64, `max_components` 50 000, `decode_timeout` 5 min) et
  `workers.org_limit` (2) ; `ingest.decode` enregistré dans `main.go` avec
  `WithOrgLimit` et `WithTimeout`.
- Écrans (fr, en, clair, sombre ; planche « 4a » : liste d'instantanés et références en
  rail) : onglet « Instantanés » de la fiche projet (références et dernier instantané,
  instantanés de la référence choisie avec commit, agent, composants par origine et
  identifications faibles, dernières réceptions avec état et erreur traduite), détail d'un
  instantané (métadonnées, composants filtrables par nom/purl, origine, type,
  identification faible ; origine IA avec sa confiance), téléchargement du SBOM reçu ou
  réencodé ; colonne « Dernier instantané » de la liste des projets. Composants CSS
  portés : `origin`, `snapshot`, `status--danger`, `row--selected`.
- Jeux d'essai `testdata/sbom/` (CycloneDX 1.5, 1.6, 1.7, SPDX 2.3, Syft JSON ; hôtes
  Debian 12, RHEL 8.6, Alpine 3.20, Ubuntu 24.04 ; dépôt avec et sans enrichissement IA),
  provenance dans `testdata/sbom/README.md`, fichiers attendus dans `golden/`.
- Fuzzing natif : `FuzzCanonicalPURL`, `FuzzPrecheck` (comparé à `encoding/json`),
  `FuzzNormalize`, `FuzzDecode`.
- ADR 0015 et 0016 ; `architecture.md` (§ 5, 6, 8, 11), `docs/operations.md`
  (« Ingestion »), modèle de menace, `config.example.yaml`.

### Décisions

- **ADR 0015** **[à relire]** : décodage dans le processus worker, sous bornes préalables,
  délai et plafond par organisation ; sous-processus écarté tant qu'aucune mesure ne le
  justifie (limite mémoire fiable seulement par cgroup).
- **ADR 0016** **[à relire]**, notamment :
  - canonicalisation des purl = celle de packageurl-go v0.1.7 (golang en minuscules, « : »
    non encodé dans la version) ;
  - identification faible portée par l'élément d'ensemble, pas par le composant ;
  - CPE et empreintes de fichier accumulés sur le composant, hors de l'empreinte
    d'inventaire ;
  - même commit renvoyé avec un autre inventaire : l'ensemble de l'instantané est
    remplacé (`replaced`) ;
  - instantané courant = plus récente date de scan déclarée (refus d'une date plus d'une
    heure en avance) ;
  - envoi impossible à stocker (gzip corrompu, trop gros décompressé) → ingestion
    `failed` sans blob ; dépassement de la taille reçue → 413 sans ingestion ;
  - doublon de dépôt (même blob, référence, commit) → 200 avec l'ingestion existante ; un
    hôte crée toujours une ingestion ;
  - **validation à la réception sans l'énumération des licences SPDX des schémas
    CycloneDX** (elle refusait « Artistic-dist », écrit par Syft en CycloneDX 1.6) ; les
    téléchargements réencodés passent le schéma officiel strict (licence trop récente
    écrite en nom).
- **Bornes par défaut** **[à relire]** : 32 Mio reçus, 64 Mio décompressés, profondeur 64,
  50 000 composants, 5 min par décodage, 2 jobs lourds simultanés par organisation ;
  plafonds de configuration : 4 096 Mio, profondeur 8 à 1 000.
- Composants CycloneDX retenus : ceux que Syft lit comme paquets (application,
  framework, library, firmware, modèle d'IA) ; `metadata.component` et la racine SPDX
  exclus.
- Composant écarté (compté dans `skipped_count`) plutôt que tronqué quand son nom (512),
  sa version (256) ou son purl (2 048) dépassent les bornes ; CPE (32), licences (32),
  empreintes (16), modèle (128), preuve (16 Kio) : excédent ignoré.
- Détail d'erreur limité au pointeur JSON d'une violation de schéma ; rien du contenu
  journalisé.
- `jobs.org_id` reçoit sa clé étrangère (point laissé ouvert par T02 et T03).
- Syft JSON : pas de schéma embarqué (la décision ne vise que CycloneDX et SPDX) ; le
  décodeur de Syft fait foi.
- Réencodage des téléchargements dans la requête web (bornée par les bornes d'ingestion),
  à partir du SBOM d'origine décodé par Syft ; les propriétés `lotor:` et `evidence` ne
  sont reportées que dans le SBOM reçu.

### Écarts

- La fiche demande la validation « par les schémas JSON officiels » : exception de
  l'énumération des licences à la réception (voir Décisions), consignée dans l'ADR 0016.
- La directive `go` monte à 1.26.8 (exigence de Syft v1.55.0).
- `internal/sbom/schema` : paquet nouveau, sous `internal/sbom` (déjà classé métier dans
  `archtest`).
- L'état « muet » d'un agent reste fondé sur le dernier contact (T04) : le fonder sur le
  dernier instantané demande une règle par nature d'agent, laissée à T07/T08.

### ADR créés

0015, 0016.

### Mesures

- **Ingestion de 5 000 composants** (CycloneDX 1.6 synthétique, 1 089 Kio de JSON,
  114 Kio en gzip, PostgreSQL 16 local, 4 cœurs, sans `-race`) : réception 30 ms ;
  décodage et rangement 0,93 s (bornes préalables, schéma, Syft, normalisation, upsert de
  5 000 composants, ensemble et éléments, instantané). Rangement seul : 0,35 s pour un
  nouvel ensemble, 0,16 s pour un nouveau commit au même inventaire.
- Décodage seul (ADR 0015) : hôte Ubuntu de 837 paquets 0,21 à 0,36 s selon le format ;
  pic du tas d'environ trente fois la taille du document (326 Mio pour 50 000 composants
  et 10 Mio).
- Couverture (unitaires et intégration) : `sbom` 92,7 %, `sbom/schema` 86,2 %,
  `sbom/syft` 88,5 %, `inventory` 86,3 %, `ingest` 86,0 %, `agent` 85,6 %, `web` 80,4 %,
  `config` 97,4 %.

### Pour les lots suivants

- **T06 (analyse)** : enregistrer le handler de `inventory.AnalysisKind`
  (`analysis.ref`, charge `inventory.AnalysisPayload{RefID}`, clé
  `inventory.AnalysisUniqueKey`) dans `main.go` avec `jobs.WithOrgLimit(cfg.Workers.OrgLimit)` ;
  il lit `ref_current` (instantané et ensemble courants) sous verrou de la référence. Le
  SBOM d'origine : `ingest.Service.Blob(ctx, org, snapshot.BlobID)` et le format dans
  `snapshots.format`. Rattacher chaque résultat de Grype à son composant par
  `sbom.ComponentPURL(pkg.PURL, pkg.Name, pkg.Version)` puis `components.purl` de
  l'organisation : les purl de l'ingestion viennent des mêmes décodeurs de Syft. Les
  composants d'une analyse : `component_set_items` de l'ensemble courant (index
  `component_set_items_component_idx` pour la recherche inverse). Le job d'analyse est déjà
  mis en file par chaque ingestion qui change l'ensemble courant : des jobs `analysis.ref`
  attendront en file tant que T06 n'est pas fusionné.
- **T07 (agent serveur)** : envoyer par `createIngestion` (client généré
  `internal/agentclient/gen` : `CreateIngestionWithBodyWithResponse` avec un corps
  multipart construit à la main, parties `context` puis `sbom`, SBOM en gzip,
  `Content-Type: application/gzip`), `ref.kind = host`, `ref.name` = nom de la référence
  d'hôte reçue de `listAgentProjects`, sans `commit`, `scanned_at` de l'hôte. Suivre l'état
  par `getIngestion` ; un envoi identique quotidien n'avance que la date de dernière
  analyse. Format conseillé : Syft JSON ou CycloneDX 1.6 (le serveur accepte 1.5 à 1.7,
  SPDX 2.3). Gérer 413 (`error.ingest.too_large`) et 404 (`error.ingest.ref_unknown`).
- **T08 (agent dépôt)** : même route avec `ref.kind` `branch` ou `tag` et le `commit`
  (40 ou 64 caractères hexadécimaux) ; renvoyer le même SBOM pour le même commit est sans
  effet (200, ingestion existante). Rattrapage : `TrackedRef.last_snapshot.commit` de
  `listAgentProjects`, puis envoi des commits manquants **du plus ancien au plus récent**
  (l'instantané courant est le plus récent par date de scan). Enrichissement IA (T12) :
  propriétés CycloneDX `lotor:origin` (`ia`), `lotor:confidence` (0 à 1),
  `lotor:model`, champ `evidence` ; un composant sans purl est accepté (identification
  faible).
- **T09 (recherche)** : `components (org_id, purl_base)` indexé ; `components.hashes`
  au format `algorithme:valeur` en minuscules (index à ajouter pour `sha256:`) ; recherche
  sur `ref_current` + `component_set_items` + `components`.
- **T17 (rétention)** : les blobs sont dédoublonnés et partagés entre ingestions et
  instantanés ; les ensembles peuvent être partagés par plusieurs instantanés.
