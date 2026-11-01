# 0049 — Purge des conteneurs archivés depuis longtemps

- Statut : Accepté
- Date : 2026-11-01
- Lot : T18

## Contexte

Un conteneur que l'agent ne signale plus est archivé après `containers.archive_after`
(7 jours, ADR 0040) ; il revient s'il redémarre. Les conteneurs éphémères (noms aléatoires
hors Compose) accumulent des projets archivés, avec leurs instantanés et constats, que
la rétention des instantanés (ADR 0039) réduit sans jamais les supprimer. ADR 0040 et T13
ont renvoyé la purge à T18, « avec la rétention ».

## Décision

- La **rétention nocturne** (`retention.snapshots_org`) supprime, après la réduction des
  historiques et avant la suppression des orphelins, les projets des conteneurs **archivés
  pour absence** (`archived_absent`) depuis plus de `containers.purge_after`, avec tout
  leur historique : instantané courant, analyses, constats (et leur historique, violations,
  envois), réceptions, instantanés, références, statistiques. Ensembles, SBOM et
  différences devenus orphelins partent avec les étapes communes. **[à relire]**
- **Durée par défaut : 180 jours** d'archivage (soit plus de six mois sans signalement),
  `0` désactive ; elle doit valoir au moins `retention.days` : la fenêtre où tout
  l'historique est gardé est passée quand le projet disparaît. Elle s'applique que
  `retention.enabled` soit vrai ou non (réglage distinct). **[à relire]**
- **Jamais purgés** : un conteneur **archivé à la main** (son archivage dit à l'agent de
  l'ignorer : le supprimer le ferait revenir comme nouveau projet) et un conteneur qui
  porte une **décision de triage** (le journal des décisions est en ajout seul, le rôle
  d'exécution ne peut pas l'effacer, et une décision documente un jugement). **[à relire]**
- **Journal d'audit** : un événement `project.purged` par conteneur, acteur système, avec
  l'hôte et la date d'archivage ; le journal d'audit lui-même n'est jamais purgé (ses
  lignes ne référencent pas les projets par clé étrangère).
- **Concurrence** : lots de 50, candidats verrouillés (`FOR UPDATE SKIP LOCKED`) et leurs
  références verrouillées comme par l'ingestion ; un conteneur qui réapparaît pendant le
  passage attend le verrou puis est recréé comme nouveau projet. Idempotent.

## Conséquences

- Un conteneur revenu après sa purge repart sans historique (nouveau projet).
- Les tableaux et la fiche d'un hôte cessent de grossir avec les conteneurs éphémères.
- Un conteneur trié reste indéfiniment (archivé) : le retirer demanderait de retirer ses
  décisions, ce que le journal en ajout seul ne permet pas. Rare et assumé.

## Alternatives écartées

- **Archivage sans suppression** (garder le projet, purger ses données) : laisse les lignes
  qui encombrent la fiche de l'hôte, sans gain de clarté.
- **Job distinct** de la rétention : même cadence, même verrouillage et mêmes orphelins à
  nettoyer ensuite ; un seul passage est plus simple à surveiller.
- **Purge des conteneurs archivés à la main** : ferait revenir les conteneurs que
  l'utilisateur a demandé d'ignorer.
