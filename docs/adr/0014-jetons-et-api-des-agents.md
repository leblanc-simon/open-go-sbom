# 0014 — Jetons et API des agents : format, résolution de l'organisation, limitation par jeton

- Statut : Accepté
- Date : 2026-10-31
- Lot : T04

## Contexte

T04 ouvre l'API des agents (`/api/v1/agent/*`) : inscription d'un agent serveur avec un
jeton d'inscription, signal de vie et liste des projets confiés avec un jeton d'agent. Le
§ 10 de l'architecture fixe l'essentiel (préfixe par nature, identifiant public, secret de
256 bits haché en SHA-256, comparaison en temps constant, révocation immédiate, date de
dernier usage) ; restaient à trancher l'écriture exacte du jeton, la façon de retrouver
l'organisation d'un jeton alors que toute lecture de ses tables exige de la connaître
(RLS, ADR 0012), la limitation par jeton et le modèle des projets confiés.

## Décision

- **Format** : `lotor_<nature>_<identifiant public>_<secret>`, natures `agt` et `enr`
  (`pat` réservé à l'API utilisateur). Identifiant public de 128 bits et secret de 256
  bits tirés par `crypto/rand`, écrits en base32 minuscule sans remplissage (26 et 52
  caractères) : ni `_` ni `-` dans les parties, donc un découpage sans ambiguïté, un jeton
  sélectionnable d'un double-clic, et une seule écriture acceptée (forme canonique
  vérifiée). Seuls l'identifiant public et le SHA-256 du secret sont stockés ; l'interface
  affiche « `lotor_agt_` + 6 caractères de l'identifiant » pour reconnaître un jeton.
- **Organisation d'un jeton** : deux fonctions de `crossorg` (migration 007),
  `lotor_agent_token_org(public_id)` et `lotor_enrollment_token_org(public_id)`, ne
  renvoient que l'identifiant de l'organisation, et seulement si elle est active. Le
  secret, la révocation, l'expiration et l'état de l'agent sont vérifiés ensuite dans
  `InOrg`, sous la RLS. `public_id` est unique sur toute l'instance. Un jeton mal formé est
  refusé sans requête.
- **Refus** : tant que le secret n'est pas vérifié, la réponse est toujours
  `error.token.invalid` (401) ; une fois le secret vérifié, l'agent reçoit la cause
  (`error.token.revoked`, `error.token.expired`, `error.agent.disabled`,
  `error.enrollment.exhausted`), utile pour diagnostiquer et sans risque : il détient le
  jeton. Un jeton d'inscription n'ouvre que `enroll`, un jeton d'agent tout le reste.
- **Dernier usage** : `last_used_at` du jeton et `last_seen_at` de l'agent ne sont écrits
  qu'une fois par minute au plus, pour ne pas transformer chaque lecture en écriture.
- **Limitation** : `ratelimit` d'open-go-base reçoit l'option `WithKeyFunc` (évolution du
  § 23, PR #2 d'open-go-base) ; la clé est l'identifiant public du jeton **authentifié**
  (`agent_api.rate_limit`, 120 par minute par défaut). Les jetons refusés sont comptés par
  IP (`agent_api.failure_rate_limit`, 30 par minute) : un client qui enchaîne les refus
  reçoit 429 sans gêner les agents authentifiés de la même IP. `internal/ratelimit` n'a
  plus d'objet et disparaît.
- **Projets confiés** : `projects.agent_id` (un projet a au plus un agent), avec une clé
  étrangère composite `(org_id, agent_id, kind)` vers `agents (org_id, id, kind)` : un
  projet n'est confié qu'à un agent de même nature. Un index unique partiel sur
  `(org_id, agent_id) WHERE kind = 'host'` garantit qu'un agent serveur couvre un seul hôte
  (décision de la fiche). Désactiver un agent révoque ses jetons et lui retire ses projets.
- **Inscription** (une transaction) : jeton relu sous verrou et revérifié, agent créé (nom
  = nom d'hôte, unique parmi les agents actifs), puis projet de l'hôte : celui que désigne
  le jeton, sinon celui qui suit déjà ce nom d'hôte s'il n'a pas d'agent actif, sinon un
  projet créé avec les étiquettes du jeton ; jeton d'agent tiré (sans expiration), usage
  consommé, journal. Un hôte déjà suivi par un agent actif est refusé (409).
- **Références suivies** retirées par `removed_at` plutôt que supprimées : l'historique
  des instantanés (T05) survit à un retrait, et réajouter la référence la réactive.

## Conséquences

- Résoudre un jeton coûte une fonction `crossorg` puis une transaction `InOrg` (deux
  allers-retours), sans donnée d'organisation hors RLS.
- La limitation est en mémoire par instance (comme celle d'open-go-base) : derrière un
  répartiteur à N instances, la limite effective d'un jeton peut atteindre N fois la
  valeur configurée.
- `lotor_*_token_org` sont des ajouts à `crossorg`, inscrits au tableau de l'ADR 0012.
- T05 contrôle l'écriture d'un agent par `project.RefForAgent` ; T07 ajoutera la colonne
  qui porte la demande de scan (`scan_requested` vaut toujours `false` d'ici là).

## Alternatives écartées

- **Organisation inscrite dans le jeton** (identifiant public qui contient l'UUID de
  l'organisation) : aucune fonction `crossorg`, mais un jeton qui révèle son organisation
  et un format lié au modèle de données ; la fonction ne renvoie rien de plus que ce que
  le jeton aurait porté.
- **Table globale d'index des jetons** : donnée d'organisation hors RLS, contraire au
  principe 6 de l'architecture.
- **Limiteur maison dans `internal/ratelimit`** : quelques dizaines de lignes, mais un
  doublon de la résolution d'IP et de la réponse 429 d'open-go-base, que le § 23 prévoyait
  d'éviter.
- **Table d'affectation agent × projet** : plusieurs agents par projet n'ont pas d'usage
  (les écrans n'en montrent qu'un) et la règle « un hôte par agent serveur » n'y serait
  plus vérifiable par une contrainte.
- **Base64url** pour les parties du jeton : plus court, mais `_` et `-` y figurent, ce qui
  rend le découpage et la sélection ambigus.
