# T05 — Ingestion des SBOM et inventaire

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T02, T04 | À faire |

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
  JSON 2.3, Syft JSON ; lecture des propriétés `ogsbom:` et du champ `evidence` ; encodage
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

- [ ] Chaque format d'exemple produit le `Document` attendu (fichiers « golden »), avec
      qualificatifs `distro`, `arch` et `epoch` et CPE conservés.
- [ ] Un SBOM malformé, trop gros, trop profond ou trop riche produit une ingestion
      `failed` avec une clé d'erreur, sans instantané partiel, avant tout décodage complet.
- [ ] Deux SBOM qui ne diffèrent que par l'horodatage et le numéro de série ont la même
      empreinte d'inventaire.
- [ ] Deux commits successifs d'un dépôt sans changement de dépendances : deux instantanés,
      un seul ensemble d'inventaire.
- [ ] Deux envois identiques d'un hôte : un seul instantané, date de dernière analyse mise
      à jour.
- [ ] Un même purl dans deux organisations donne deux lignes `components` distinctes.
- [ ] Un agent ne peut pas envoyer pour une référence qui ne lui est pas confiée.
- [ ] Le SBOM téléchargé en CycloneDX et en SPDX est valide pour son format.
- [ ] Ingestion de 5 000 composants : durée mesurée et consignée dans le Journal.

## Tests attendus

Fuzzing de la canonicalisation des purl, des bornes préalables et du décodage. Intégration
de bout en bout (envoi → job → instantané), y compris ingestions concurrentes. Tests
d'isolement sur les routes et les écrans.

## Points à trancher

- Purl `generic` pour les composants sans purl, ou rejet du composant ?
- Validation par les schémas JSON officiels (nouvelle dépendance) ou décodage strict seul ?

## Journal

_À remplir pendant la réalisation._
