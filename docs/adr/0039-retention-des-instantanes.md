# 0039 — Rétention des instantanés : fenêtre de 90 jours, dernier instantané de chaque mois au-delà, orphelins supprimés

- Statut : Accepté
- Date : 2026-11-01
- Lot : T17

## Contexte

Un dépôt actif produit un instantané par commit, un serveur un par changement
d'inventaire : sans rétention, instantanés, réceptions, ensembles d'inventaire et SBOM
bruts croissent sans fin (et pèsent sur le quota `ingest.max_org_storage_mib`, ADR 0030).
La décision du 1er novembre 2026 (fiche T17) fixe la politique par défaut : tous les
instantanés sont gardés 90 jours, puis un par mois, sans limite de durée ; le dernier
instantané d'une référence n'est jamais supprimé. La fiche demande une rétention
configurable (nombre ou durée) et le nettoyage par job des ensembles et des SBOM devenus
orphelins, et eux seuls. La recherche à une date passée (T21) s'appuiera sur cet
historique et doit savoir à partir de quand il est réduit.

## Décision

### Politique

Configuration `retention.*` (`LOTOR_RETENTION_*`) : `enabled` (vrai), `days` (90, de 1
à 36 500), `count` (0), `monthly` (vrai). La coupure vaut « maintenant − `days` jours ».
Pour chaque référence, un instantané est supprimé seulement si **toutes** ces conditions
tiennent :

1. il a été scanné **et** reçu (`created_at`) avant la coupure : un instantané envoyé en
   retard reste au moins `days` jours ;
2. il n'est pas parmi les `count` plus récents de sa référence, ni le plus récent (le
   courant, `ref_current`) ;
3. il n'est pas le dernier de ceux qui précèdent la coupure : c'est l'instantané **en
   vigueur au début de la fenêtre**, gardé pour qu'à toute date de la fenêtre
   l'instantané en vigueur existe encore (sans lui, une date juste après la coupure
   n'aurait plus d'état) ;
4. avec `monthly`, il n'est pas le **dernier de son mois** (UTC, calculé parmi les
   instantanés antérieurs à la coupure) : le dernier du mois est l'état du parc à la fin
   du mois ; la règle 3 en est le cas particulier du mois à cheval sur la coupure ;
5. il n'est pas l'instantané de la dernière analyse de sa référence (`ref_analyses`).

« Le dernier de chaque mois » plutôt que « le premier » : il décrit l'état en fin de
mois, et la règle 3 en découle naturellement.

### Exécution

- Échéance quotidienne `retention.snapshots_all` (02:30 UTC, une instance) qui met en
  file un `retention.snapshots_org` par organisation, archivées comprises (liste par
  `crossorg.ListOrganizations`, aucune fonction `crossorg` nouvelle).
- Par référence, **sous le verrou de la référence** que prend aussi l'ingestion
  (`tracked_refs … FOR UPDATE`), sélection des instantanés à supprimer puis suppression,
  avec leurs réceptions ; une ingestion concurrente ne peut pas changer l'ordre entre la
  décision et la suppression. Le job `inventory.diff` de la référence est remis en file
  (nouveaux couples consécutifs, ADR 0038).
- Les **réceptions terminées** (`done`, `failed`) reçues avant la coupure sont
  supprimées : c'est un journal de réception, et une réception en échec retiendrait son
  SBOM pour toujours. Celles des instantanés supprimés partent avec eux.
- **Orphelins** : un ensemble d'inventaire que ni un instantané, ni `ref_current`, ni
  `ref_analyses` ne référence, un SBOM que ni un instantané ni une réception ne
  référence, sont supprimés par lots de 500, avec leurs éléments et différences
  (cascade). Ils le sont même rétention désactivée : ce sont des restes (commit remplacé,
  rétention passée). Les composants ne sont pas purgés : ils sont référencés par les
  constats et leur volume est borné par la diversité des paquets, pas par l'historique.
- **Concurrence avec l'ingestion** : l'ingestion verrouille l'ensemble ou le SBOM
  qu'elle réutilise (`SELECT … FOR KEY SHARE`) avant de le référencer, et le recrée s'il
  vient d'être supprimé ; la rétention verrouille ses candidats en sautant ceux qui sont
  tenus (`FOR UPDATE SKIP LOCKED`), puis ne supprime que ceux qui sont toujours orphelins
  vus de l'instruction suivante. Une référence validée entre les deux est vue ; une
  ingestion n'échoue jamais pour un orphelin supprimé sous elle.
- Les différences qui ne relient plus deux instantanés consécutifs sont supprimées.
- Un constat garde son instantané tant qu'il existe : `findings.snapshot_id` et
  `finding_events.snapshot_id` deviennent facultatifs, `ON DELETE SET NULL`
  (migration 017) ; le constat et son historique restent.
- Index ajoutés pour que chaque suppression ne parcoure pas les tables qui la
  référencent (constats, événements, états, analyses, instantanés par SBOM, réceptions
  par SBOM et par date).

### Horizon, pour la recherche à une date passée (T21)

Chaque passage actif enregistre dans `snapshot_retention` (table d'organisation) son
bilan et l'**horizon** : la plus récente coupure appliquée, qui ne recule jamais.
`inventory.ReadRetention` le lit.

- Pour une date **postérieure ou égale à l'horizon**, l'instantané en vigueur de chaque
  référence existe toujours (règles 1 à 3) : la recherche à cette date est exacte.
- Pour une date **antérieure**, l'historique est réduit au dernier instantané de chaque
  mois (ou au seul instantané en vigueur à la coupure sans `monthly`) : l'état retenu
  est celui de la fin du mois précédent, ou plus ancien ; les changements intermédiaires
  sont perdus. T21 affiche alors l'avertissement « résultats partiels ».
- Sans ligne (rétention jamais passée ou désactivée), l'historique est complet.
- Allonger `days` ne rend pas ce qui a été supprimé : l'horizon garde la coupure la plus
  récente.

## Conséquences

- Le volume par référence est borné : au plus les instantanés de la fenêtre, plus un par
  mois au-delà (environ douze par an).
- Une réanalyse ne porte que sur les instantanés courants : la rétention ne touche jamais
  l'état courant ni les constats ouverts.
- Le premier passage sur une instance ancienne peut supprimer beaucoup de lignes : il
  procède référence par référence, en transactions courtes, et un passage interrompu est
  repris le lendemain (chaque étape est idempotente).
- `docs/operations.md` documente la politique, ses réglages et ses effets.

## Alternatives écartées

- **Le premier instantané de chaque mois** : il décrit le début du mois, et il faudrait
  garder en plus l'instantané en vigueur à la coupure.
- **Rétention par nombre seul** : la fiche et la décision parlent de durée ; `count`
  s'ajoute à la fenêtre (les N plus récents en plus des `days` derniers jours) sans la
  remplacer, pour qu'une référence peu active garde son historique récent.
- **Purge des ensembles par compteur de références** : un compteur maintenu à chaque
  ingestion ajouterait une écriture concurrente sur une ligne partagée ; la recherche
  d'orphelins, quotidienne et indexée, suffit.
- **Supprimer les constats résolus de l'instantané supprimé** : ils sont l'historique de
  la sécurité du projet (date de correction, tableau de bord) ; seul leur lien vers
  l'instantané disparaît.
- **Garder les SBOM bruts des instantanés supprimés** pour l'audit : ils sont le gros du
  volume ; un instantané gardé garde son SBOM.
