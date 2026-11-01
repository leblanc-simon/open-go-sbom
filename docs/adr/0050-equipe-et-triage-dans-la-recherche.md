# 0050 — Équipe et statut de triage dans la recherche

- Statut : Accepté
- Date : 2026-11-01
- Lot : T18

## Contexte

Le cahier des charges (§ 8) combine toute recherche avec un filtre « équipe » et montre,
pour une recherche par vulnérabilité, le statut de triage. T16 a filtré la recherche par
les équipes visibles sans filtre explicite ; T14 a livré le triage sans le montrer dans la
recherche. Les deux ont été renvoyés à T18.

## Décision

- **Filtre `team`** (identifiants, plusieurs valeurs s'additionnent) pour toute recherche,
  à l'écran, dans l'API et l'export ; il s'ajoute à la visibilité du compte (une équipe
  invisible ou d'une autre organisation ne donne rien, l'écran garde sa case cochée sous
  le nom « Équipe inconnue » sans révéler de nom). L'équipe de chaque projet figure dans
  les résultats (`team` de l'API, colonnes `team` de l'export, `team_id` du JSON).
- **Statut de triage** effectif de chaque constat d'une recherche par vulnérabilité (écran,
  avec lien vers la fiche du constat ; `triage_status` de l'API et de l'export), **tous
  statuts montrés** par défaut : à « sommes-nous touchés ? », « non affecté » est une
  réponse. Filtre `triage` (statuts, plusieurs valeurs). **[à relire]**
- Le filtre `triage` sur une recherche qui n'est pas par vulnérabilité est **refusé**
  (`error.search.triage_vulnerability_only`, 400), pas ignoré : une URL partagée ne change
  pas de sens en silence (même règle que les filtres inconnus, ADR 0024) ; l'écran ne le
  propose que pour une recherche par vulnérabilité.
- **Recherche par composant** : les vulnérabilités ouvertes, la pire sévérité, KEV, risque
  et versions corrigées d'une occurrence **écartent les constats triés « non affecté » ou
  « faux positif »**, comme les listes de constats et le tableau de bord (ADR 0035,
  0037). **[à relire]**
- Colonnes de l'export ajoutées **en fin de ligne** (`team`, `triage_status`) pour ne pas
  décaler celles qu'un script lit déjà par position.

## Conséquences

- Une recherche par composant peut afficher « aucune vulnérabilité » pour un composant dont
  tous les constats sont triés « faux positif » ; la recherche par vulnérabilité les montre
  toujours, avec leur statut.
- Le paramètre `triage` invalide une URL de recherche par composant qui le porterait.

## Alternatives écartées

- **Ignorer `triage`** hors recherche par vulnérabilité : URL au sens changeant.
- **Masquer par défaut** les constats « non affecté » dans la recherche par vulnérabilité,
  comme les listes : la recherche sert précisément à établir l'exposition, statut compris.
- **Filtre d'équipe à valeur unique** (comme la liste des projets) : les autres filtres de
  la recherche sont multiples.
