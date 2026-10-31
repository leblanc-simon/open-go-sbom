# T14 — Triage et VEX

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | À faire |

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

- [ ] Une décision d'organisation s'applique à tous les projets concernés, et une décision de
      projet la surcharge pour ce projet seulement.
- [ ] Un constat apparu après une décision hérite de son statut.
- [ ] Un risque accepté échu revient « à analyser » le jour même.
- [ ] Les exports VEX sont valides contre les schémas OpenVEX et CycloneDX.
- [ ] Un aller-retour export puis import dans le même format redonne les mêmes décisions,
      justifications comprises.
- [ ] Un `viewer` ne peut pas trier.

## Tests attendus

Tables de calcul du statut effectif ; validation des exports par schéma ; import de VEX
d'exemple ; isolement.

## Points à trancher

Aucun.

## Journal

_À remplir pendant la réalisation._
