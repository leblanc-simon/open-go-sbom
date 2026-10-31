# 0020 — Agent serveur : envoi conditionnel confirmé par le serveur, scan à la demande, état muet

- Statut : Accepté
- Date : 2026-10-31
- Lot : T07

## Contexte

L'agent serveur n'envoie un SBOM que lorsque l'inventaire a changé (cahier des charges,
§ 6) ; sinon « un simple signal de vie met à jour la date de dernière analyse ». La fiche
T07 demande une empreinte calculée comme côté serveur et conservée dans le répertoire
d'état, un scan à la demande transmis par `scan_requested`, et le contexte de l'hôte.
Restaient à trancher : comment un signal de vie fait avancer la date de dernière analyse
(T05 ne l'avance que sur un envoi identique), que faire si l'état local ment (base du
serveur restaurée, envoi refusé après coup), quel format envoyer, où ranger le contexte
de l'hôte, comment remettre une demande de scan, et sur quoi fonder l'état « muet »
(laissé par T04 et T05 sur le dernier contact).

## Décision

- **Empreinte calculée par l'agent avec le code du serveur** : l'agent décode son propre
  SBOM par `sbom/syft.Decode` et calcule `sbom.Fingerprint`, exactement ce que fait
  l'ingestion. Ni horodatages ni identifiants du document n'y entrent : deux scans sans
  changement de paquets ont la même empreinte (testé sur `testdata/rootfs`).
- **Compte rendu d'inventaire dans le signal de vie** : à empreinte inchangée, l'agent
  envoie `heartbeat` avec `inventory` (projet, référence d'hôte, empreinte, date du scan).
  Le serveur, référence verrouillée comme pour un rangement (`inventory.Confirm`),
  compare à l'empreinte de l'ensemble courant (`component_sets.fingerprint`) : égale, il
  avance `last_scanned_at` de l'instantané courant et répond `inventory: current` ;
  sinon (aucun instantané, autre ensemble, référence inconnue ou de dépôt) il répond
  `outdated` et l'agent envoie son SBOM. L'état local n'est donc qu'une économie : le
  serveur reste la source de vérité (principe 3). L'agent ne retient l'empreinte qu'une
  fois le SBOM **rangé** (`getIngestion` : `done`), si bien qu'un envoi refusé est refait
  au cycle suivant.
- **Format envoyé : Syft JSON**, compressé en gzip. C'est le format natif de Syft et de
  Grype, qui reçoit le SBOM d'origine (§ 12) : distribution, métadonnées des paquets et
  emplacements y sont complets. Le serveur l'accepte depuis T05.
- **Scan à la demande** : `agents.scan_requested_at` (migration 011), posé par le bouton
  « Scanner maintenant » de la fiche d'un projet d'hôte (analyste ou administrateur,
  journalisé `agent.scan_requested`) ; une demande en attente garde sa date. Le signal
  de vie suivant la **remet une seule fois** (lue et effacée dans sa transaction) et
  l'agent démon lance aussitôt un cycle. En mode oneshot, la demande attend le prochain
  passage du timer.
- **Contexte de l'hôte sur l'agent** : `agents.host_context` (jsonb, 4 Kio au plus) et
  `host_context_at`, dernier contexte annoncé (os-release, noyau, architecture, nom
  d'hôte, durée du scan), joint à chaque envoi (`IngestionContext.host`) et à chaque
  compte rendu. Valeurs bornées et imprimables, validées par le serveur. Il n'est pas
  historisé par instantané.
- **État muet par nature d'agent** : un agent serveur est muet quand son hôte n'a plus
  été **inventorié** (dernière date de dernière analyse de ses projets, ou sa création
  s'il n'a jamais rien rangé) depuis `agent.SilentAfter` (3 jours), même s'il répond
  encore : des envois refusés ou des scans en échec se voient. Un agent dépôt reste muet
  sur son dernier contact, puisqu'il n'envoie rien tant que ses dépôts ne bougent pas.
- **Étiquettes de l'agent** : `EnrollRequest.labels` (configuration de l'agent) complète
  les étiquettes du jeton d'inscription sur un projet créé par l'inscription ; celles du
  jeton, choisies par un administrateur, l'emportent.

## Conséquences

- Un hôte sans changement coûte, par jour, un scan local et un signal de vie ; rien
  n'est stocké de plus côté serveur.
- Un réessai d'envoi après une réponse perdue peut créer une ingestion de plus pour un
  hôte (sans effet sur les instantanés : « inchangé »).
- Changer `sbom.Fingerprint` (préfixe de version) fait renvoyer leur SBOM à tous les
  agents d'une ancienne version, ce qui est sans risque.
- Le décodage de son propre SBOM fait entrer l'adaptateur `sbom/syft` dans le binaire de
  l'agent (déjà autorisé : ce n'est pas un paquet serveur).

## Alternatives écartées

- **Signal de vie sans compte rendu** : simple, mais la date de dernière analyse
  n'avancerait plus, et un serveur qui aurait perdu l'inventaire ne le saurait jamais.
- **Toujours envoyer le SBOM** et laisser le serveur constater « inchangé » : le serveur
  le sait faire depuis T05, mais le cahier des charges veut un envoi conditionnel (trafic,
  stockage de blobs, travail de décodage).
- **Empreinte du document (SHA-256 du JSON)** : change à chaque scan (horodatages,
  identifiants), donc inutile.
- **Demande de scan remise jusqu'à ce qu'un scan postérieur arrive** : plus robuste à un
  agent qui s'arrête au mauvais moment, mais dépend de l'horloge de l'agent ; une horloge
  en retard relancerait des scans sans fin. L'utilisateur peut redemander.
- **CycloneDX 1.6** comme format d'envoi : plus compact (environ 1,7 fois), mais perd des
  métadonnées de paquets que Grype exploite.
