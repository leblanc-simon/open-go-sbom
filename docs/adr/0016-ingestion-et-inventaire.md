# 0016 — Ingestion et inventaire : identité des composants, empreinte, règles d'instantané, validation

- Statut : Accepté
- Date : 2026-10-31
- Lot : T05

## Contexte

T05 range les SBOM des agents en instantanés de références suivies, avec des ensembles
d'inventaire adressés par contenu (§ 8 et § 11 de l'architecture). Il fallait fixer ce
qui identifie un composant, ce qui entre dans l'empreinte d'un ensemble, comment se
comportent les envois répétés, ce que devient un envoi impossible à stocker, et comment
appliquer la décision « validation par les schémas officiels » sans refuser des SBOM
légitimes.

## Décision

- **Identité d'un composant** : son purl canonique, unique par organisation. La
  canonicalisation est celle de `packageurl-go` v0.1.7 (validé au § 5) : schéma et type en
  minuscules, espace de noms et nom ajustés par type (minuscules pour deb, rpm, apk, alpm,
  golang, github, bitbucket, composer… ; minuscules et « _ » → « - » pour pypi),
  qualificatifs aux clés en minuscules, triés, sans valeur vide, chaque partie encodée de
  façon unique (« : » n'est pas encodé dans la version : `1:2.36-9`). Aucun qualificatif
  n'est retiré. La forme écrite doit se relire à l'identique. Un purl absent ou illisible
  donne `pkg:generic/<nom>@<version>` et l'« identification faible » (`weak_id`), portée
  par l'élément d'ensemble (c'est le document qui l'identifie mal, pas le composant).
  `sbom.ComponentPURL` applique la règle ; l'analyse (T06) l'applique aux paquets de Grype.
- **Les paquets viennent du décodeur de Syft**, celui qu'utilise Grype, si bien qu'un même
  blob donne les mêmes purl à l'ingestion et à l'analyse. CycloneDX est relu pour ce que
  Syft ignore (empreintes, portée, propriétés `lotor:`, `evidence`), SPDX pour les sommes
  de contrôle. Le composant décrit par le document lui-même (`metadata.component`, racine
  SPDX) n'est pas un composant ; les composants CycloneDX de type `file`,
  `operating-system`, `container`, `device`, `data`… non plus (seuls ceux que Syft lit comme
  paquets).
- **Ce qui est porté par le composant** (accumulé, jamais retiré) : CPE et empreintes de
  fichier, bornés à 64. **Ce qui est porté par l'élément d'ensemble** : origine, confiance
  (quatre décimales), modèle, portée, identification faible, licences, preuve (JSON
  canonique, clés triées, 16 Kio au plus).
- **Doublons d'un même purl dans un document** : fusionnés indépendamment de l'ordre —
  Syft l'emporte sur l'IA, puis la confiance la plus haute, puis un ordre total sur les
  champs ; listes unies ; portée la plus contraignante ; faible seulement si toutes les
  mentions le sont.
- **Empreinte d'inventaire** : SHA-256 d'une sérialisation versionnée
  (`lotor-inventory-v1`), champs préfixés par leur longueur, des éléments triés par purl ;
  ni horodatage, ni numéro de série, ni outil, ni ordre du document, ni CPE.
- **Instantanés** : dépôt, un instantané par (référence, commit) ; le même commit renvoyé
  avec le même inventaire ne crée rien (`unchanged`), avec un autre inventaire il remplace
  l'ensemble de l'instantané (`replaced` : le dernier scan d'un commit fait foi). Hôte : un
  envoi identique à l'inventaire courant n'avance que `last_scanned_at` (`unchanged`), sinon
  un nouvel instantané. L'instantané courant (`ref_current`) est le plus récent par date de
  scan déclarée par l'agent, puis par création ; un instantané inchangé ne redevient pas
  courant. `analysis.ref` est mis en file, dans la même transaction, quand l'ensemble
  courant change ; sa clé d'unicité (`ref:<id>`) fond les mises en file successives.
- **Réception** : un dépôt qui renvoie le même SBOM (même empreinte de blob) pour la même
  référence et le même commit retrouve l'ingestion existante (200, rien de créé) ; un hôte
  crée toujours une ingestion (c'est elle qui avance la date de dernière analyse). Un envoi
  qui dépasse la taille reçue admise est refusé (413) sans ingestion ; un envoi qu'on ne
  peut pas stocker (flux gzip corrompu, trop gros une fois décompressé, vide) devient une
  ingestion `failed` avec sa clé, sans blob, comme les refus du décodage. Le blob est stocké
  en gzip (tel que reçu s'il l'était déjà), dédoublonné par le SHA-256 du JSON décompressé.
- **Validation** : schémas officiels embarqués de CycloneDX 1.5, 1.6, 1.7 et SPDX 2.3, sans
  référence réseau ni assertion de `format` (défaut de draft-07). À la réception, la seule
  exception est l'énumération des identifiants de licence SPDX des schémas CycloneDX
  (`spdx.schema.json`), remplacée par « une chaîne » : figée à la publication de chaque
  version, elle refuse les identifiants plus récents qu'écrit Syft (« Artistic-dist » en
  CycloneDX 1.6). Les SBOM que le serveur produit (téléchargement réencodé) passent le
  schéma officiel sans exception : un identifiant plus récent y est écrit en nom de
  licence. Syft JSON n'a pas de schéma embarqué ; son décodeur fait foi.
- **Détail d'erreur** : seule une violation de schéma porte un détail, le pointeur JSON de
  la première violation (200 caractères au plus), jamais une valeur du document ; rien du
  contenu n'est journalisé.

## Conséquences

- Deux commits sans changement de dépendances coûtent une ligne d'instantané ; deux scans
  quotidiens identiques d'un hôte coûtent une ligne d'ingestion et une mise à jour de date.
- Un agent dont l'horloge avance de plus d'une heure est refusé (`validation.ingest.scanned_at`) ;
  un agent qui rescanne un commit ancien en dernier le rend courant : l'agent dépôt rattrape
  les commits du plus ancien au plus récent.
- Changer la canonicalisation ou l'empreinte demande une nouvelle version de la
  sérialisation (les anciens ensembles ne sont plus réutilisés) et, pour les purl, une
  migration des composants.

## Alternatives écartées

- **CPE dans l'empreinte** : deux SBOM au même inventaire mais aux CPE différents (version
  de Syft) auraient deux ensembles ; Grype lit les CPE du blob d'origine, pas de la base.
- **Instantané courant d'un dépôt = commit le plus récent** : le serveur ne connaît pas
  l'ordre des commits ; la date de scan est la seule information fiable sans accès à la
  forge.
- **Refus synchrone (4xx) de tout envoi mal formé** : séparerait les erreurs en deux canaux ;
  l'ingestion `failed` donne un statut et une clé uniformes, visibles dans l'interface.
- **Validation stricte des licences à la réception** : refuserait des SBOM légitimes et
  récents ; l'identifiant de licence n'est pas une donnée d'identité (Grant les analysera en
  T20).
