# 0037 — Écrans du triage : fiche du constat au lieu du tiroir, constats masqués par défaut, page VEX du projet, décisions de l'organisation

- Statut : Accepté
- Date : 2026-11-01
- Lot : T14

## Contexte

La planche « 6 · Triage d'un constat » du design de référence montre un tiroir
(`dialog`) ouvert au-dessus de la fiche vulnérabilité : résumé du constat, statuts en
liste de choix (justification VEX sous « non affecté », date sous « risque accepté »),
portée (projet ou organisation), commentaire, historique en frise. L'interface de lotor
fonctionne sans JavaScript (§ 14) et sous une CSP stricte ; la fiche T14 demande aussi
des filtres par statut effectif, le masquage par défaut des constats « non affecté » et
« faux positif », l'export et l'import VEX.

## Décision

- **Fiche d'un constat** `GET /o/{slug}/projects/{project}/findings/{id}` : le contenu
  du tiroir devient une page de même structure (résumé, panneau, historique), sous les
  onglets du projet ; son formulaire poste sur `…/triage`. Le tiroir modal demanderait
  du JavaScript pour s'ouvrir, piéger le focus et se fermer ; une page fonctionne au
  clavier et sans script, et l'URL d'un constat se partage. Les champs complémentaires
  d'un choix (justification, échéance, plage) apparaissent par `:has(input:checked)` en
  CSS, sans attribut `required` (un champ masqué bloquerait l'envoi) : le serveur
  valide. La justification VEX est exigée dans l'interface, le commentaire aussi ; un
  import peut n'avoir qu'une déclaration d'impact.
- La liste des justifications propose les deux vocabulaires en groupes d'options
  (CycloneDX, celui de la maquette, puis OpenVEX) : la valeur choisie est stockée telle
  quelle (ADR 0036).
- **Historique** : décisions qui concernent le constat (du projet pour son composant, de
  l'organisation pour sa famille dont la plage contient sa version) et événements de
  l'analyse (ouverture, résolution, réouverture), fusionnés du plus récent au plus
  ancien ; la décision appliquée est marquée. L'« assignation à une équipe » de la
  maquette n'existe pas dans lotor (un projet appartient à une équipe, ADR 0034) : elle
  n'est pas reprise.
- **Retrait** d'une décision : action irréversible au sens du § 14 (« retirer »), donc
  lien vers la page de confirmation commune, puis `POST`.
- **Onglet « Constats »** : colonne « Triage » (statut écrit et forme du repère, lien
  vers la fiche) et filtre par statut effectif ; par défaut, les constats « non affecté »
  et « faux positif » sont masqués, avec leur nombre et un lien « Tout afficher ». Les
  décomptes de l'en-tête restent ceux de tous les constats ouverts. La fiche
  vulnérabilité reçoit la même colonne.
- **Onglet « VEX »** d'un projet : nombre de déclarations, téléchargement OpenVEX et
  CycloneDX, import pour le projet (analyste ou administrateur de l'équipe).
- **Rubrique « Triage »** de l'organisation (`/o/{slug}/triage`, administrateurs) :
  décisions d'organisation en vigueur avec le nombre de constats ouverts qu'elles
  qualifient, retrait, import d'un VEX d'organisation.
- Statuts de triage dans `status.*` (racine transverse, § 18), justifications dans
  `vex_justification.*`.

## Conséquences

- Aucune ligne de JavaScript nouvelle ; les composants nouveaux (`choice-list`,
  `timeline`, statuts de triage) suivent ceux de la maquette, portés dans
  `web/static/css`.
- Les tests de la matrice des droits et d'isolement par route couvrent les nouvelles
  routes d'eux-mêmes (table `orgRoutes`).

## Alternatives écartées

- **Tiroir en amélioration progressive** (page sans JavaScript, tiroir avec) : deux
  rendus à tenir accessibles pour un gain visuel ; reportable si la recette du lot 2 le
  demande.
- **Masquer aussi « corrigé »** : il attend la confirmation d'un instantané et doit rester
  visible jusque-là.
