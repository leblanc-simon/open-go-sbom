# 0036 — Échanges VEX : OpenVEX 0.2.0 et CycloneDX 1.6, correspondance des statuts et des justifications, marques de lotor, sans nouvelle dépendance

- Statut : Accepté
- Date : 2026-11-01
- Lot : T14

## Contexte

T14 exporte les décisions d'un projet en OpenVEX et en CycloneDX VEX et importe les VEX
d'éditeurs. Les deux formats n'ont ni les mêmes statuts ni les mêmes justifications
(fiche T14) ; lotor a deux statuts propres (« faux positif » en OpenVEX, « risque
accepté jusqu'à une date » dans les deux) ; la fiche exige qu'un aller-retour export
puis import dans le même format redonne les mêmes décisions, justifications comprises,
que la justification d'origine soit stockée telle quelle, et qu'un export vers l'autre
format note la justification d'origine quand la correspondance perd de l'information.
Les exports doivent être valides contre les schémas officiels.

## Décision

### Formats et dépendances

- **OpenVEX 0.2.0** en JSON, écrit et lu par des structures propres au projet
  (`internal/triage/vex`) ; schéma officiel (`openvex_json_schema.json`, licence CC0)
  embarqué et compilé par `santhosh-tekuri/jsonschema`, déjà validé (§ 5).
- **CycloneDX 1.6** (VEX dans un BOM) par `CycloneDX/cyclonedx-go`, déjà validé ; validé
  par le schéma strict de `sbom/schema`. L'import lit aussi les versions antérieures
  (1.4 à 1.7) par le décodeur de la bibliothèque.
- Aucune nouvelle dépendance : `openvex/go-vex`, présent dans le graphe de Grype, a été
  écarté (il aurait fallu le promouvoir en dépendance directe pour une vingtaine de
  lignes de structures, et ses types portent des comportements — fusion, sérialisation
  canonique — dont lotor n'a pas besoin).

### Correspondance des statuts

| lotor | OpenVEX | CycloneDX (`analysis.state`) |
| --- | --- | --- |
| à analyser | `under_investigation` | `in_triage` |
| affecté | `affected`, commentaire en `action_statement` | `exploitable` |
| non affecté | `not_affected` + justification, commentaire en `impact_statement` | `not_affected` + justification |
| faux positif | `not_affected`, `component_not_present`, marque `[lotor:status=false_positive]` | `false_positive` |
| risque accepté | `affected`, marque `[lotor:status=risk_accepted;expires=AAAA-MM-JJ]` | `exploitable`, `response: [will_not_fix]`, propriétés `lotor:triage_status`, `lotor:triage_expires` |
| corrigé | `fixed` | `resolved` (`resolved_with_pedigree` lu comme corrigé) |

### Justifications

Stockées telles quelles (OpenVEX ou CycloneDX). Table de correspondance
(`triage.Justification.In`) :

| CycloneDX | vers OpenVEX | OpenVEX | vers CycloneDX |
| --- | --- | --- | --- |
| `code_not_present` | `vulnerable_code_not_present` | `component_not_present` | `code_not_present` |
| `code_not_reachable` | `vulnerable_code_not_in_execute_path` | `vulnerable_code_not_present` | `code_not_present` |
| `requires_configuration` | `vulnerable_code_cannot_be_controlled_by_adversary` | `vulnerable_code_not_in_execute_path` | `code_not_reachable` |
| `requires_dependency` | `component_not_present` | `vulnerable_code_cannot_be_controlled_by_adversary` | `requires_environment` |
| `requires_environment` | `vulnerable_code_cannot_be_controlled_by_adversary` | `inline_mitigations_already_exist` | `protected_by_mitigating_control` |
| `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` | `inline_mitigations_already_exist` | | |

Un export vers l'autre liste écrit la correspondance **et note la justification
d'origine** — toujours, et pas seulement quand la correspondance n'est pas réciproque :
même une correspondance réciproque change de liste, et l'aller-retour perdrait sinon la
valeur stockée. La lecture reprend la note si elle correspond à la justification lue.

### Marques de lotor

Le schéma d'OpenVEX refuse toute propriété supplémentaire : les informations propres à
lotor vont dans `status_notes`, sous la forme `[lotor:clé=valeur;…]` suivie du texte
éventuel (commentaire d'un statut sans autre champ de texte). En CycloneDX, elles sont
des propriétés de l'espace de noms `lotor:` (§ 11 de l'architecture). Un outil tiers lit
des statuts VEX standards ; lotor relit ses propres exports sans perte.

### Contenu des exports

Une déclaration par couple (composant, vulnérabilité) des constats **ouverts** du projet
qui ont une décision (du projet ou héritée de l'organisation), le composant désigné par
son purl canonique (OpenVEX : `products[].@id` et `identifiers.purl` ; CycloneDX :
composant du BOM, `bom-ref` = purl). Les constats « à analyser » sans décision n'y
figurent pas (une déclaration `under_investigation` réimportée deviendrait une décision
explicite). Auteur : l'organisation ; outil : `lotor <version>`.

### Imports

- Document borné à 1 Mio et 5 000 déclarations (produits développés). Format reconnu au
  contenu (`@context` OpenVEX, `bomFormat` CycloneDX). Une déclaration au statut, à la
  justification ou à l'état inconnus, ou sans purl, est écartée et comptée ; le
  document n'est pas refusé pour autant (VEX d'éditeurs imparfaits).
- OpenVEX : les sous-composants d'un produit sont les composants visés s'il y en a, le
  produit sinon. CycloneDX : `affects[].ref` désigne un composant du BOM (`bom-ref`) ou
  directement un purl.
- **Pour un projet** : une déclaration vise les composants des constats du projet de
  même famille, de même version (toutes si elle n'en donne pas) et aux qualificatifs
  compatibles (ceux de la déclaration présents à l'identique) ; sans composant
  correspondant, elle est écartée (un purl exact sans qualificatifs ne retrouverait
  jamais `…?arch=amd64&distro=debian-12`).
- **Pour l'organisation** : la famille (`purl_base`), restreinte par une plage `vers`
  exacte à la version déclarée s'il y en a une ; elle vaut aussi pour les constats à
  venir.
- Auteur des décisions : `vex:<source>`, la source étant saisie à l'import ou, à défaut,
  l'auteur déclaré par le document ; le compte qui importe est noté.
- L'interface accepte le fichier jusqu'à 1 Mio (au lieu de 64 Kio pour un formulaire),
  pour un compte authentifié seulement ; en deçà de la mémoire de `ParseMultipartForm`,
  csrfx lit le formulaire en mémoire, sans fichier temporaire (piège de T11).
- L'API utilisateur expose l'export (`GET /api/v1/orgs/{org}/projects/{project}/vex`) ;
  l'import reste à l'interface, les jetons personnels étant en lecture seule (ADR 0025).

## Conséquences

- Les exports passent les schémas officiels (tests `TestExportsValidAgainstSchemas` et
  test d'écran) ; un aller-retour dans le même format, ou d'un format à l'autre et
  retour, redonne statut, justification, commentaire et échéance
  (`TestRoundTripSameFormat`, `TestRoundTripAcrossFormats`,
  `TestVEXRoundTripRestoresDecisions`).
- CSAF n'est pas pris en charge (non demandé) ; il s'ajouterait comme troisième format
  du même paquet.

## Alternatives écartées

- **Ne noter la justification d'origine que si la correspondance n'est pas
  réciproque** : l'aller-retour d'un format à l'autre ramenait une justification de
  l'autre liste (trouvé par le test d'aller-retour).
- **Propriétés supplémentaires dans OpenVEX** : refusées par le schéma officiel.
- **Exporter aussi les constats sans décision** (`under_investigation`) : un réimport
  aurait transformé un défaut en décision explicite, contraire à l'aller-retour.
- **Import pour un projet par purl exact** : les qualificatifs des purl d'inventaire
  (distribution, architecture) font échouer la plupart des correspondances avec un VEX
  d'éditeur.
