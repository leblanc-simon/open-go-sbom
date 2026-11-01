// Package notify tient les canaux de notification d'une organisation et l'envoi des
// violations de politiques (T15, ADR 0046).
//
//   - Canaux (Channel) : e-mail (SMTP de l'instance), webhook générique signé, Matrix,
//     Mattermost, Slack. Les secrets (clé HMAC, jeton Matrix, URL d'un webhook entrant)
//     sont chiffrés par internal/secret, la ligne du canal en données associées ; ils ne
//     sont jamais relus par les écrans ni journalisés.
//   - Envois : Queue, appelé par internal/policy dans la transaction qui ouvre des
//     violations, crée un envoi par couple (canal, violation) — jamais deux, d'où l'absence
//     de doublon — et met en file le job notify.send du canal pour un envoi immédiat. Un
//     envoi de résumé attend le passage quotidien (notify.digest_all, puis notify.digest_org
//     par organisation), qui relance aussi les envois immédiats restés en attente.
//   - notify.send regroupe en un message les envois en attente d'un canal (100 au plus),
//     écarte ceux dont la violation est résolue, envoie, puis marque les envois envoyés. Un
//     échec est réessayé par la file (30 tentatives à délai croissant) ; l'identifiant du
//     message dérive de ses envois, si bien qu'une tentative répétée garde le même
//     identifiant (X-Lotor-Delivery, transaction Matrix).
//   - Messages composés dans la langue de l'organisation (Catalog), lien vers la page des
//     violations quand l'URL publique est connue ; webhook générique en JSON, signé par
//     Sign : HMAC-SHA256(secret, horodatage + "." + corps), horodatage dans
//     X-Lotor-Timestamp (format : docs/notifications.md).
//   - L'envoi lui-même passe par Sender, implémenté hors du métier par internal/delivery.
package notify
