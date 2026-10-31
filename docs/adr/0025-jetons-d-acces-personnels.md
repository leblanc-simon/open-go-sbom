# 0025 — Jetons d'accès personnels : donnée du compte, lecture seule, appartenance vérifiée à chaque requête

- Statut : Accepté
- Date : 2026-10-31
- Lot : T09

## Contexte

T09 ouvre la première route de l'API utilisateur, `GET /api/v1/orgs/{org}/search`, avec des
jetons d'accès personnels (`ogsbom_pat_`, préfixe réservé par l'ADR 0014) : « création et
révocation depuis le profil, lecture seule, limités aux organisations du compte ». Le § 8
de l'architecture rangeait `personal_access_tokens` parmi les tables d'organisation, à
côté des jetons d'agent.

## Décision

- **Table globale** `personal_access_tokens` (migration 013), comme `sessions`,
  `account_settings` et `session_auth` : un jeton est une donnée du **compte**, créée
  depuis le profil (hors de toute organisation), et ne contient aucune donnée
  d'organisation. Seuls l'identifiant public (unique sur l'instance) et le SHA-256 du
  secret sont stockés. Écart au § 8, mis à jour.
- **Portée** : lecture seule (l'API utilisateur n'a que des `GET`), sur les organisations
  dont le propriétaire est membre **au moment de chaque requête** : la garde de l'API
  appelle `crossorg.Access(slug, user_id)` (fonction existante de la garde de l'interface)
  et répond 404 sinon, comme l'interface. Retirer un membre ou archiver une organisation
  coupe l'accès à la requête suivante, sans toucher au jeton. **Aucune nouvelle fonction
  `crossorg`** : le jeton se lit dans une table globale, l'organisation par la fonction de
  la garde.
- **Format et vérification** : ceux de l'ADR 0014, mis en commun dans `internal/token`
  (natures `agt`, `enr`, `pat`) ; refus `error.token.invalid` tant que le secret n'est pas
  vérifié, puis `error.token.revoked`, `error.token.expired`,
  `error.token.account_inactive` (compte désactivé). Dernier usage écrit une fois par
  minute au plus.
- **Durée de vie obligatoire** : 7, 30, 90 (défaut), 180 ou 365 jours, pas de jeton sans
  expiration ; 20 jetons actifs au plus par compte ; création et révocation au journal
  d'audit de l'instance (`personal_token.created`, `personal_token.revoked`).
- **Limitation** : par jeton (`user_api.rate_limit`, 60 par minute), refus comptés par IP
  (`user_api.failure_rate_limit`, 30), comme l'API des agents.
- **Session dans l'API** : non prise en charge à ce stade. L'écran de recherche est rendu
  par le serveur et sert ses propres exports ; aucun JavaScript n'appelle l'API.

## Conséquences

- Un jeton couvre toutes les organisations du compte : un compte membre de plusieurs
  organisations a un seul jeton pour ses scripts, et la portée suit ses appartenances.
- Un jeton volé donne la lecture de ce que voit son propriétaire, jusqu'à son expiration
  ou sa révocation ; il ne permet ni écriture ni administration.
- La session avec en-tête CSRF dans l'API utilisateur (§ 14) reste à faire quand un
  écran appellera l'API en JavaScript.

## Alternatives écartées

- **Jeton par organisation** (table d'organisation sous RLS, comme le § 8) : moindre
  privilège, mais la liste du profil exigerait une transaction par organisation, un jeton
  par organisation pour un même script, et l'organisation résolue par le slug avant le
  jeton (`ogsbom_org_id_by_slug`, réservée à l'administration). La portée « organisations du
  compte » de la fiche décrit un jeton du compte.
- **Restriction facultative à une organisation** : une colonne d'organisation dans une
  table globale, pour un besoin non exprimé ; à reconsidérer avec les équipes (T16).
- **Jetons sans expiration** : un secret oublié dans un script reste valable indéfiniment.
