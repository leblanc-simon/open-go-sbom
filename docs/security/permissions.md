# Matrice des droits

<!-- Fichier généré depuis internal/tenant/permission.go : ne pas le modifier à la main.
     go test ./internal/tenant -run TestPermissionsDocument -update -->

Qui voit, trie et modifie quoi dans une organisation (T16, ADR 0034). Le rôle
d'organisation vaut **membre** ou **administrateur** ; les droits sur un projet, un agent ou
une équipe viennent du rôle du compte **dans l'équipe de la ressource** : lecteur, analyste
ou administrateur d'équipe. L'administrateur d'organisation voit et gère tout.

Cette matrice est la source des contrôles de l'application (`tenant.Allowed`) et des tests
par route (`internal/web`, test `TestRoutePermissionsFollowMatrix`) : document, code et tests
dérivent de la même table.

## Règles de visibilité

- Un membre ne voit que les projets des équipes dont il est membre, quel que soit son
  rôle d'équipe ; un membre sans équipe ne voit aucun projet.
- Le filtre s'applique à toutes les surfaces de lecture : listes, fiches, recherche et ses
  exports, tableau de bord et ses statistiques, pages des vulnérabilités et des
  composants, API utilisateur (jetons personnels compris), agents.
- Une ressource d'une équipe invisible répond **404**, comme une ressource d'une autre
  organisation ; une action refusée sur une ressource visible répond **403**.
- Un agent sans équipe (agent d'organisation) n'est visible et géré que par les
  administrateurs d'organisation ; il peut servir les projets de toutes les équipes.
- Les projets créés par un jeton d'inscription héritent de l'équipe du jeton, et l'agent
  inscrit aussi.
- Un compte devient membre d'une organisation en acceptant une invitation ; la réponse à
  l'invitation est la même, que le compte existe ou non.

## Matrice

| Permission | Portée | Description | Administrateur d'organisation | Administrateur d'équipe | Analyste | Lecteur | Membre hors de l'équipe |
| --- | --- | --- | :---: | :---: | :---: | :---: | :---: |
| `org.view` | organisation | Tableau de bord, recherche, exports et API utilisateur, limités aux projets visibles | oui | oui | oui | oui | oui |
| `members.view` | organisation | Voir la liste des membres de l'organisation | oui | oui | oui | oui | oui |
| `members.manage` | organisation | Inviter un compte, changer un rôle d'organisation, retirer un membre, révoquer une invitation | oui | — | — | — | — |
| `teams.manage` | organisation | Créer, renommer et supprimer une équipe | oui | — | — | — | — |
| `org.manage` | organisation | Paramètres et journal d'audit de l'organisation | oui | — | — | — | — |
| `triage.org` | organisation | Décider du triage pour toute l'organisation, importer un VEX d'organisation, retirer une décision d'organisation | oui | — | — | — | — |
| `policy.manage` | organisation | Créer, modifier, supprimer et prévisualiser les politiques de l'organisation | oui | — | — | — | — |
| `channel.manage` | organisation | Créer, modifier, supprimer et essayer les canaux de notification de l'organisation | oui | — | — | — | — |
| `team.view` | équipe | Voir l'équipe, ses membres et ses projets | oui | oui | oui | oui | — |
| `team.members` | équipe | Ajouter ou retirer un membre de l'équipe, changer son rôle d'équipe | oui | oui | — | — | — |
| `project.view` | équipe | Fiche, constats, instantanés, composants et SBOM d'un projet de l'équipe | oui | oui | oui | oui | — |
| `project.scan` | équipe | Demander un scan à l'agent serveur d'un projet | oui | oui | oui | — | — |
| `finding.triage` | équipe | Trier les constats d'un projet, importer un VEX pour ce projet, retirer une décision du projet | oui | oui | oui | — | — |
| `project.create` | équipe | Créer un projet dans l'équipe | oui | oui | — | — | — |
| `project.manage` | équipe | Modifier, archiver, réactiver un projet, le confier à un agent | oui | oui | — | — | — |
| `project.move` | équipe | Rattacher un projet à une autre équipe (droit exigé dans les deux équipes) | oui | oui | — | — | — |
| `agent.view` | équipe | Voir les agents de l'équipe | oui | oui | oui | oui | — |
| `agent.manage` | équipe | Créer un agent de l'équipe, ses jetons, le désactiver ; jetons d'inscription de l'équipe | oui | oui | — | — | — |

Pour une permission d'organisation, les colonnes des rôles d'équipe valent pour tout
membre qui n'est pas administrateur d'organisation.
