# 0047 — Statut de commit publié par l'agent dépôt

- Statut : Accepté
- Date : 2026-11-01
- Lot : T15

## Contexte

Le verdict des politiques doit apparaître sur chaque commit dans la forge (GitHub et
GitLab). Seul l'agent dépôt détient les secrets des forges (§ 19) : c'est lui qui publie,
après avoir envoyé le SBOM et attendu le verdict du serveur, de façon bornée. T12 modifie
le même agent en parallèle.

## Décision

- **Déroulement** : après l'envoi d'un commit, l'agent suit l'ingestion puis interroge
  `GET /api/v1/agent/snapshots/{id}/verdict` (5 s au départ, doublé jusqu'à 30 s), au plus
  `status.timeout` (15 min). Il publie « en attente » dès que le serveur fournit son résumé
  traduit, puis le verdict : conforme → `success`, non conforme → `failure` (GitLab
  `failed`), ingestion en échec → `error` (GitLab `canceled`, pour ne pas se lire comme un
  échec des politiques). Le délai passé, le statut reste « en attente » : l'agent ne publie
  aucun texte qui ne vienne du serveur. Le commit suivant de la même référence attend :
  l'ordre des statuts suit celui des instantanés. **[à relire]**
- **Nom du statut** : `status.context` (`lotor`) ; description = résumé du serveur
  (140 caractères au plus) ; lien = page des constats du projet.
- **Désactivé par défaut** (`status.enabled: false`) : la publication demande une
  permission de plus sur la forge ; une installation existante ne doit pas se mettre à
  échouer à la montée de version. **[à relire]**
- **GitHub** : jeton d'installation séparé, restreint au dépôt et à `statuses: write`, en
  cache à part de celui du clonage (`contents: read`) : le jeton qui passe dans
  l'environnement de git ne peut toujours rien écrire (SEC-10). L'application doit avoir la
  permission « Commit statuses : Read and write ».
- **GitLab** : `POST /projects/:id/statuses/:sha` ; le compte de service doit avoir la
  portée `api` (au lieu de `read_api`) et le rôle Developer.
- **Échecs** : une publication refusée ou un verdict illisible est journalisé (sans
  secret) et n'empêche ni l'envoi ni le commit suivant.

## Conséquences

- Les commits rattrapés en nombre allongent le rattrapage d'au plus `status.timeout`
  chacun quand le serveur est lent ; un serveur sans base de vulnérabilités laisse les
  statuts en attente.
- Le compte de service GitLab gagne un droit d'écriture sur l'API : à confiner aux projets
  suivis.

## Alternatives écartées

- **Publication par le serveur** : il faudrait lui confier les secrets des forges,
  contraire au § 19.
- **Attente asynchrone** (le commit suivant part pendant l'attente) : le commit précédent
  ne serait plus l'ensemble courant de la référence et son verdict ne viendrait jamais.
- **Statut `error` à l'expiration du délai** : il faudrait un texte propre à l'agent, qui
  n'a pas de traductions ; « en attente » reste vrai.
