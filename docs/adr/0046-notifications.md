# 0046 — Notifications : canaux, secrets, envois dédoublonnés et réessayés

- Statut : Accepté
- Date : 2026-11-01
- Lot : T15

## Contexte

Les violations doivent partir sur des canaux par organisation (e-mail SMTP, webhook
générique signé en HMAC avec horodatage, Matrix, Mattermost, Slack), en envoi immédiat ou
en résumé quotidien selon la règle, sans doublon, avec des réessais pour un canal en panne,
des secrets chiffrés et des messages traduits dans la langue de l'organisation. Le mailer
utilise `net/smtp` (pas de nouvelle dépendance). Le métier n'ouvre aucune connexion
(§ 4 de l'architecture).

## Décision

- **Paquets** : `internal/notify` (métier) tient les canaux, les envois et compose les
  messages ; `internal/delivery` (serveur, hors métier, comme `download`) envoie : HTTP et
  SMTP derrière l'interface `notify.Sender`.
- **Secrets** : clé HMAC du webhook, jeton Matrix, URL d'un webhook entrant Slack ou
  Mattermost (qui vaut identifiant) chiffrés par `internal/secret`, la ligne du canal
  (organisation et identifiant) en données associées ; jamais réaffichés (champ vide :
  secret gardé), jamais journalisés, absents de l'audit. Les réglages sans secret
  (destinataires, URL du webhook générique, serveur et salon Matrix) sont en `jsonb`.
- **Envois** (`notification_deliveries`) : une ligne par couple (canal, violation), clé
  primaire, créée dans la transaction qui ouvre la violation (`notify.Queue`) — une
  violation n'est jamais envoyée deux fois sur un canal ; une nouvelle violation (après
  résolution) l'est de nouveau. Le job `notify.send` d'un canal (clé d'unicité par canal et
  mode) regroupe les envois en attente en un message (100 au plus), écarte ceux dont la
  violation est résolue (`skipped`), envoie, puis les marque `sent`. Un échec est réessayé
  par la file (30 tentatives à délai croissant, soit une dizaine d'heures avec les délais
  par défaut) ; le passage quotidien relance les envois restés en attente. L'identifiant
  du message dérive des envois du lot : une tentative répétée après une réponse perdue
  garde le même identifiant (`X-Lotor-Delivery`, identifiant de transaction Matrix, que
  Matrix écarte de lui-même). **[à relire]**
- **Résumé quotidien** : `notify.digest_all` à `notify.digest_hour` UTC (7 h), puis
  `notify.digest_org` par organisation, qui met en file le résumé de chaque canal.
- **Webhook générique** : `POST` JSON (`docs/notifications.md`), en-têtes
  `X-Lotor-Event`, `X-Lotor-Delivery`, `X-Lotor-Timestamp` (secondes Unix) et
  `X-Lotor-Signature: sha256=<hex>` = `HMAC-SHA256(secret, horodatage + "." + corps)` ;
  clé de 16 caractères au moins, fournie par l'administrateur. **[à relire]**
- **Slack, Mattermost** : message texte par webhook entrant, caractères `& < >` échappés
  (un nom de règle ne forme ni lien ni mention). **Matrix** : `m.notice` par l'API client
  v3, jeton d'accès d'un compte. **E-mail** : texte UTF-8 en quoted-printable, objet encodé,
  en-têtes protégés contre l'injection, `Auto-Submitted: auto-generated`.
- **SSRF** : les URL sont saisies par des administrateurs d'organisation ; le client HTTP
  refuse à la connexion (après résolution DNS) les adresses de bouclage, privées, de lien
  local, partagées, non spécifiées et de multidiffusion, sauf
  `notify.allow_private_networks` ; aucune redirection suivie, **aucun mandataire**, durée
  bornée (`notify.timeout`), réponse lue sur 64 Kio au plus ; l'erreur ne cite jamais
  l'URL. Le serveur SMTP, choisi par l'exploitant, n'est pas soumis à la garde.
  **[à relire]**
- **SMTP** : `starttls` (exigé, le mot de passe n'est jamais envoyé avant TLS), `tls`
  (implicite) ou `none` (relais local, authentification refusée par la configuration).
- **Messages** dans la langue de l'organisation (`organizations.default_language`), lien
  vers la page des violations si `notify.public_url` est configuré, 20 violations
  détaillées par message lisible puis « … et N autres ».
- **Essai** (« envoyer un test ») : envoi synchrone depuis l'écran, issue affichée et
  journalisée (`channel.tested`, avec la clé d'erreur éventuelle).
- **Droits** : `channel.manage` (administrateurs d'organisation) ; 50 canaux et 20
  destinataires au plus.

## Conséquences

- Un destinataire de webhook doit vérifier la signature et refuser un horodatage trop
  ancien (cinq minutes conseillées) ; il peut dédoublonner par `X-Lotor-Delivery`.
- Un canal désactivé garde ses envois en attente ; le réactiver les remet en file.
- Sans mandataire, un serveur qui ne sort que par un proxy ne peut joindre que les canaux
  e-mail ; à reprendre si un exploitant le demande (le proxy rendrait la garde SSRF
  inopérante).

## Alternatives écartées

- **Envoi direct depuis la transaction de l'évaluation** : un canal lent bloquerait
  l'évaluation, et un échec ferait perdre le message.
- **Un message par violation** : une analyse qui ouvre trente violations enverrait trente
  messages.
- **Bibliothèque de courriel** (`go-mail`, `gomail`) : `net/smtp` suffit (STARTTLS,
  PLAIN), sans nouvelle dépendance, comme décidé.
- **Clé HMAC tirée par le serveur et affichée une fois** : plus sûre contre une clé faible,
  mais une étape d'écran de plus ; une longueur minimale suffit au premier lot.
