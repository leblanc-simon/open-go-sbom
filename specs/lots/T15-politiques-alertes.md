# T15 — Politiques, alertes et statuts de commit

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T14 | À faire |

## Objectif

Exprimer des règles déclaratives, être prévenu quand elles sont violées sur les bons
canaux, et voir le verdict directement sur chaque commit dans la forge.

## Périmètre

**Inclus**

- `internal/policy` : règles en CEL sur le contexte (projet, étiquettes, composant, constat,
  statut de triage, agent) ; modèles fournis : KEV sur un projet de production, critique avec
  correctif disponible depuis plus de 30 jours, agent muet depuis 7 jours (le modèle
  « licence AGPL » est livré désactivé jusqu'à T20). Évaluation après chaque analyse et
  chaque jour. Violations datées ; drapeau « bloquante ».
- `internal/notify` : canaux par organisation (e-mail SMTP, webhook générique signé en HMAC
  avec horodatage, Matrix, Mattermost, Slack), secrets chiffrés par `internal/secret`,
  envoi par jobs avec réessais, résumé quotidien ou envoi immédiat selon la règle, bouton
  « envoyer un test », messages traduits dans la langue de l'organisation.
- Mailer `net/smtp` (TLS implicite ou STARTTLS), configuration et documentation.
- Messages produits dans la langue de l'organisation (définie en T03).
- Verdict d'un instantané : `GET /api/v1/agent/snapshots/{id}/verdict` (en attente, conforme,
  non conforme, résumé, lien).
- Agent dépôt : après l'envoi, attente bornée du verdict puis publication du statut de commit
  (GitHub, GitLab, Forgejo).
- Écrans : liste et édition des règles (validation et aperçu du nombre de violations
  actuelles avant enregistrement), violations, canaux.
- Audit : création, modification et suppression des règles et des canaux, envois de test.

**Exclu** : réinitialisation de mot de passe par e-mail (hors cahier des charges).

## Conception

- Une règle invalide ou trop coûteuse est refusée à l'enregistrement (CEL compilé, coût
  borné) ; aucune règle ne s'exécute sans limite de coût.
- Les notifications sont dédoublonnées : une violation déjà notifiée ne l'est pas de nouveau
  tant qu'elle n'a pas été résolue.
- Signature des webhooks : `HMAC-SHA256(secret, horodatage + "." + corps)`, horodatage dans un
  en-tête pour permettre au destinataire de refuser les rejeux.

## Livrables

Paquets, migrations, écrans, route d'API, évolution de l'agent dépôt, documentation des
canaux et du format de webhook.

## Critères d'acceptation

- [ ] Chaque modèle de règle fournie déclenche sur un jeu construit à la main, et pas en
      dehors.
- [ ] Un canal en panne reçoit ses messages après rétablissement (réessais), sans doublon.
- [ ] Le statut de commit apparaît sur les trois forges avec le bon état.
- [ ] Une règle CEL invalide est refusée avec un message traduit qui situe l'erreur.
- [ ] Aucun secret de canal n'est lisible en base ni dans les journaux.

## Tests attendus

Tables de règles CEL ; destinataires simulés (`httptest`, serveur SMTP de test) ;
vérification de signature ; forges simulées ; isolement.

## Points à trancher

- Valider la dépendance `cel-go`.

## Journal

_À remplir pendant la réalisation._
