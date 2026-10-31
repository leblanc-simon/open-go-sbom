# 0011 — Conception de la file de traitements : horloge, prise, plafond, arrêt

- Statut : Accepté
- Date : 2026-10-31
- Lot : T02

## Contexte

L'ADR 0005 retient une file maison sur PostgreSQL ; la fiche T02 en fixe les principes
(au moins une fois, bail renouvelé, réessais à délai exponentiel, clé d'unicité qui relève
la priorité, plafond par organisation, planificateur sans verrou de session, arrêt qui
libère les baux, horloge injectable). Plusieurs points restaient ouverts : la source de
l'heure, l'ordre de prise, la rigueur du plafond, le sort d'un job interrompu par l'arrêt
ou en conflit avec un jumeau de même clé, la durabilité des transitions d'état et la forme
des échéances.

## Décision

- **Heure** : toutes les dates de la file (échéance, bail, réessai, rétention, échéances
  du planificateur) viennent d'une `jobs.Clock` côté Go, passée en paramètre aux requêtes,
  jamais de `now()` de PostgreSQL. Les tests avancent ainsi le temps sans attendre. Les
  instances doivent avoir des horloges synchronisées (NTP) ; un écart reste très inférieur
  au bail (30 s). `Enqueue`, `Retry` et le planificateur en production prennent l'horloge
  du système.
- **Prise** : une transaction par job, `FOR UPDATE SKIP LOCKED`, en deux requêtes : d'abord
  les jobs au bail expiré (worker disparu) qui n'ont pas épuisé leurs tentatives, puis les
  jobs en attente échus, par priorité décroissante, échéance et identifiant, en
  parcourant l'index partiel `jobs_pending` (une seule requête avec `OR` imposait un tri
  de tous les jobs en attente à chaque prise). La tentative est comptée à la prise : un
  job qui fait tomber son worker finit par passer `dead`.
- **Plafond par (type, organisation)**, tenu strictement entre instances : la requête de
  prise exclut les couples saturés, puis, pour un type plafonné, la transaction prend un
  verrou consultatif **de transaction** propre au couple et recompte les jobs en cours ;
  au plafond, elle s'annule et la prise recommence en excluant ce couple. Le verrou tombe
  à la validation, dont l'effet est visible du suivant (READ COMMITTED). Compatible avec
  pgbouncer.
- **Bail** : `lease_token` désigne la prise en cours. Renouvellement, fin, échec et
  libération ne s'appliquent que si le jeton est toujours le nôtre ; sinon (bail expiré et
  repris ailleurs, ou libéré par l'arrêt) le résultat est ignoré et le handler annulé.
- **Clé d'unicité** sur (type, clé) des seuls jobs en attente. Une seconde mise en file
  garde la plus haute priorité, l'échéance la plus proche et la charge du job existant ;
  elle refuse (`ErrUniqueKeyConflict`) de fusionner deux organisations. Un job en cours
  n'y figure pas : une mise en file pendant son exécution crée un nouveau job. Un job
  remis en attente (échec, arrêt) qui heurte un jumeau en attente s'efface devant lui.
- **Durabilité** : les transactions d'état du runner (prise, bail, fin) sont validées avec
  `synchronous_commit = off` (pour elles seules). Une panne de PostgreSQL dans la fraction
  de seconde qui suit perd la transaction entière : le job revient à son état précédent
  et sera rejoué, ce que la sémantique « au moins une fois » admet déjà. La mise en file,
  elle, vit dans la transaction de l'appelant. Mesure locale : 2,0 ms contre 3,4 ms par
  prise et fin.
- **Arrêt** : `Stop` cesse de prendre, attend les jobs en cours, puis, au quart du délai
  restant avant l'échéance (au plus 2 s), annule les handlers et remet leurs jobs en
  attente en une instruction, **sans compter la tentative** ni changer l'échéance. Un
  handler qui ignore l'annulation finit en arrière-plan, son résultat est ignoré.
- **Erreurs** : `jobs.Permanent(err)` envoie directement en `dead` ; une panique est un
  échec ordinaire ; `WithTimeout` borne une exécution. La dernière erreur est conservée,
  tronquée à 4 000 octets.
- **Échéances** sur une grille fixe en UTC (`Offset + k × Every`) : une échéance nouvelle
  part tout de suite, puis à chaque point ; le prochain point se calcule depuis
  l'instant de la prise, sans rattrapage des points manqués. Prise et mise en file
  partagent une transaction. Sans clé d'unicité, le job d'une échéance reçoit
  `schedule:<nom>` : des points manqués ne s'empilent pas.
- **Maintenance** sur chaque instance, chaque minute : passage en `dead` des jobs dont le
  bail a expiré pendant la dernière tentative, purge par lots (`SKIP LOCKED`) des jobs
  terminés au-delà de `workers.retention`. Les jobs `dead` restent jusqu'à leur relance ou
  suppression par l'administrateur.

## Conséquences

- Les handlers doivent être idempotents et relire en base ce que la charge référence
  (charge bornée à 16 Kio pour l'imposer).
- Un job au bail expiré passe avant un job en attente plus prioritaire : il a déjà été
  commencé, et le cas reste rare (worker disparu).
- Une horloge d'instance très décalée fausserait baux et échéances : NTP est un prérequis
  documenté dans `docs/operations.md`.
- Une prise coûte une transaction ; un test de charge de 10 000 jobs (trois runners, dix
  organisations) sert de garde-fou.

## Alternatives écartées

- **`now()` de PostgreSQL** comme seule horloge : robuste aux écarts entre instances, mais
  les tests de délais (réessais, baux, rétention, échéances) devraient attendre réellement
  ou manipuler les lignes. La fiche exige une horloge injectable.
- **Plafond approximatif** (simple exclusion dans la requête de prise) : deux workers
  simultanés le franchissent ; le plafond protège justement d'une organisation trop
  active.
- **Libération qui compte la tentative** : un déploiement fréquent épuiserait les jobs
  longs sans qu'ils aient échoué.
- **`LISTEN/NOTIFY`** pour réveiller les workers : connexion dédiée hors pool,
  incompatible avec pgbouncer en mode transaction ; la scrutation à 1 s suffit.
- **Planificateur par verrou consultatif de session** : exclu par la fiche (coupures,
  pgbouncer).
