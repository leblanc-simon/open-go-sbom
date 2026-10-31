# T07 — Agent serveur Linux

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T05 | Terminé |

## Objectif

`ogsbom-host-agent` : un binaire statique qui inventorie un hôte Linux avec Syft, avec le
moins de privilèges possible, et n'envoie un SBOM que lorsque l'inventaire a changé.

## Périmètre

**Inclus**

- `internal/agentclient` (généré depuis OpenAPI) avec réessais bornés, respect de
  `Retry-After` et certificat client facultatif.
- `internal/hostagent` : configuration (URL du serveur, jeton d'inscription, répertoire
  d'état, intervalle, exclusions, étiquettes, proxy, autorité de certification, certificat
  client, délais), inscription, scan, contexte de l'hôte, comparaison d'empreinte
  d'inventaire, envoi ou signal de vie.
- Modes `daemon` (intervalle + interrogation du signal de vie) et `oneshot` (pour un timer
  systemd).
- Scan à la demande : bouton sur la fiche du projet hôte, transmis par `scan_requested`.
- Serveur : vérification facultative du certificat client sur `/api/v1/agent/*` quand le
  TLS natif et `tls.client_ca` sont configurés.
- Unité systemd durcie et timer, paquets deb et rpm non signés.
- Binaires amd64 et arm64, `CGO_ENABLED=0`.

**Exclu** : conteneurs (T13), Windows (T22), mode hors ligne (T23), signature (T24, T26).

## Conception

- Scan de `/` avec les catalogueurs adaptés à un système installé. Exclusions par défaut :
  `/proc`, `/sys`, `/dev`, `/run`, `/var/lib/docker`, `/var/lib/containers`,
  `/var/lib/containerd`, montages réseau et systèmes de fichiers de conteneurs, plus la
  liste configurée. Les images de conteneurs relèvent de T13, jamais du SBOM de l'hôte.
- Contexte : `/etc/os-release`, version du noyau, architecture, nom d'hôte, version de
  l'agent, durée du scan.
- Empreinte d'inventaire calculée comme côté serveur (même fonction de `internal/sbom`) et
  conservée dans le répertoire d'état ; identique → signal de vie seulement.
- Sobriété : `GOMAXPROCS` et `GOMEMLIMIT` configurables avec des valeurs basses par défaut,
  durée maximale de scan ; l'unité systemd fixe `Nice=19`, `IOSchedulingClass=idle` et
  propose `CPUQuota=` en option (au prix d'un scan plus long).
- Moindre privilège : utilisateur dédié, `AmbientCapabilities=CAP_DAC_READ_SEARCH`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, écriture limitée
  au répertoire d'état, `PrivateTmp=yes`.
- Secrets (jeton d'inscription, jeton d'agent, clé du certificat client) : credentials
  systemd chiffrés ou fichiers `0600`, jamais dans le fichier de configuration.

## Livrables

Binaire, `config.example.yaml` de l'agent, unités systemd, configuration de paquets,
section « Agent serveur » de `docs/operations.md`.

## Critères d'acceptation

- [x] Sur un système de fichiers d'exemple (`testdata/rootfs`), le SBOM contient les paquets
      dpkg, rpm, apk et Python attendus, et rien sous les répertoires de conteneurs.
- [x] Deux scans sans changement : un seul envoi, puis des signaux de vie.
- [x] Le bouton « Scanner maintenant » déclenche un scan au prochain signal de vie.
- [x] L'agent tourne sans root avec l'unité fournie et lit les bases de paquets.
- [x] Avec `tls.client_ca` configuré, un agent sans certificat client valide est refusé.
- [x] Temps CPU, durée et mémoire maximale d'un scan mesurés sur la machine de référence,
      consignés, et comparés à la cible validée (voir point à trancher).
- [x] Taille des binaires consignée.

## Tests attendus

Unitaires : empreinte stable, configuration, état. Intégration : parcours complet contre un
serveur de test (`httptest` ou `ogsbom-server` réel), avec et sans mTLS.

## Décisions

Prises le 31 octobre 2026 :

- Cible CPU reformulée : temps CPU par scan et mémoire maximale bornés sur la machine de
  référence ; valeurs fixées après la première mesure puis reportées au cahier des charges ;
  `CPUQuota` proposé en option dans l'unité systemd.
- Paquets deb et rpm produits par nfpm, en directive `tool`.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T07-agent-serveur`, en parallèle de T06 et T08
(T08 fusionné pendant le lot et intégré par `git merge origin/main`).

### Livré

- **`internal/agentclient`** (client commun, commité en premier) : enveloppe du client
  généré ; transport HTTPS (autorité privée qui remplace celles du système, certificat
  client relu quand il change sur le disque, mandataire explicite ou de l'environnement,
  aucune redirection suivie) ; réessais bornés (erreur réseau, 429, 500, 502, 503, 504 ;
  délai exponentiel à gigue ; `Retry-After` respecté, abandon s'il dépasse `Retry.Max`) ;
  `*Error` (statut, clé RFC 9457, titre, détail, identifiant de requête), `IsKey`,
  `HasStatus` ; `Enroll`, `Heartbeat`, `Projects` (toutes les pages), `Upload` (multipart
  `context` puis `sbom` gzip, construit une fois et rejoué), `Ingestion`, `Wait`, `Final`,
  `WithToken`. Réponses bornées à 8 Mio. Couverture 91 %.
- **`internal/hostagent`** et `cmd/ogsbom-host-agent` : configuration
  (`OGSBOM_HOST_AGENT_*`, `deploy/host-agent/config.example.yaml`), inscription, état
  (`Store` : répertoire `0700`, jeton et `state.json` en `0600`, écritures atomiques),
  secrets (fichier privé ou credential systemd ; fichier ouvert refusé), scan Syft
  (`SyftScanner` : catalogueurs « image » d'un système installé, sans catalogage de
  fichiers, `DefaultExclusions`, montages réseau, de conteneurs et autofs lus dans
  `/proc/self/mountinfo`, `scan.exclude`), contexte de l'hôte (os-release, `uname`,
  nom d'hôte, durée), empreinte par `sbom/syft.Decode` + `sbom.Fingerprint`, envoi ou
  compte rendu, modes `daemon` (`Run` : intervalle, signaux de vie avec gigue, scan à la
  demande, reprise après échec à 15 min) et `oneshot` (`RunOnce`) ; `GOMAXPROCS` et
  `GOMEMLIMIT` posés par `main`. Couverture 83 %.
- **Serveur** : migration **009** (`agents.scan_requested_at`, `host_context`,
  `host_context_at`, contraintes « agent serveur seulement ») ; `agent.Heartbeat`
  (demande de scan remise une fois, contexte d'hôte, compte rendu d'inventaire),
  `agent.RecordHost`, `agent.RequestScan` (journal `agent.scan_requested`),
  `agent.Activity` (état muet par nature d'agent), étiquettes de l'agent à l'inscription ;
  `inventory.Confirm` ; API : `EnrollRequest.labels`, `HeartbeatRequest.inventory` et
  `.host`, `HeartbeatStatus.inventory`, `IngestionContext.host`, schémas
  `InventoryReport` et `HostContext` (code régénéré) ; mTLS exigé sur l'API des agents
  (`AgentOptions.RequireClientCert`, posé par `main` avec `tls.client_ca_file`, clé
  `error.client_cert_required`).
- **Écrans** (fr, en, clair, sombre) : « Scanner maintenant » et demande en attente,
  dernier inventaire et contexte de l'hôte sur la fiche d'un projet d'hôte ; panneau
  « Hôte » sur la fiche d'un agent serveur ; **assistant d'installation** (paquet,
  adresse du serveur, jeton déposé en `0600`, démarrage, nettoyage) sur la page qui
  affiche un jeton d'inscription. Composant CSS `install-steps`.
- **Agent dépôt** (à la demande de l'orchestrateur, après la fusion de T08) :
  `repoagent.NewServer` sur le client commun (réessais, `Retry-After`, mTLS, mandataire,
  `server.retries`), adaptateur provisoire `APIServer` supprimé, adresse `https`
  exigée ; écart retiré du Journal de T08 et de `specs/avancement.md`.
- **Déploiement** : `deploy/systemd/ogsbom-host-agent.service` (démon),
  `ogsbom-host-agent-oneshot.service` et `.timer`, durcis (`systemd-analyze security` :
  1,9) ; `deploy/host-agent/` (configuration, `sysusers.d`, scripts) ;
  `deploy/nfpm/host-agent.yaml` ; `make packages` (amd64 et arm64, deb et rpm, dans
  `make ci` et la CI) ; nfpm v2.48.0 en directive `tool`.
- **Jeu d'essai** `testdata/rootfs` (dpkg, rpm BerkeleyDB réelle de go-rpmdb, apk,
  Python ; leurres sous les stockages de conteneurs, `/proc`, un montage NFS simulé, une
  exclusion configurée), provenance dans son `README.md`.
- **Tests** : unitaires (exclusions, mountinfo, os-release, configuration, état, secrets,
  scan réel de `testdata/rootfs`, empreinte stable, cycles contre un faux serveur, démon
  et scan à la demande) ; intégration (`agent` : étiquettes, demande de scan, contexte,
  compte rendu d'inventaire avec un vrai SBOM rangé ; `inventory.Confirm` ; `web` :
  parcours complet d'un vrai agent en HTTPS, avec et sans mTLS, rôles du bouton) ;
  mesures et moindre privilège du binaire réel sous l'étiquette `measure` (hors CI).
- ADR 0020 et 0021 ; `architecture.md` (§ 5, 8, 17), `docs/operations.md` (« Agent
  serveur », TLS, agent dépôt), modèle de menace, `config.example.yaml` du serveur,
  cahier des charges (cibles).

### Décisions

- **ADR 0020** **[à relire]** : compte rendu d'inventaire dans le signal de vie (le
  serveur confirme l'empreinte ou réclame le SBOM, l'état local n'est qu'une économie) ;
  empreinte retenue seulement après rangement ; **Syft JSON** comme format d'envoi ;
  demande de scan remise une seule fois ; contexte d'hôte sur l'agent (non historisé) ;
  **état muet d'un agent serveur fondé sur son dernier inventaire** (création s'il n'a
  rien rangé), agent dépôt toujours sur son dernier contact ; étiquettes de l'agent
  complétées par celles du jeton, qui l'emportent.
- **ADR 0021** **[à relire]** : deux unités en conflit (démon recommandé, timer quotidien
  à 2 h ± 1 h) ; durcissement ; secrets (fichier privé, credential systemd, fichier ouvert
  refusé) ; HTTPS seul, pas de redirection ; mTLS : `VerifyClientCertIfGiven` au niveau
  TLS, refus de l'absence de chaîne vérifiée dans un middleware de l'API des agents, sans
  lien entre certificat et agent ; paquets nfpm, scripts qui n'activent aucune unité.
- **Demande de scan** permise aux analystes et administrateurs (une action sans
  modification de données) **[à relire]**.
- **Valeurs par défaut** **[à relire]** : `scan.interval` 24 h, `scan.poll_interval`
  5 min, `scan.max_duration` 1 h, `resources.max_procs` 1, `memory_limit_mib` 512 (limite
  douce), `MemoryMax=1536M` (dure), 5 tentatives par requête, attente du rangement 15 min,
  reprise après échec 15 min.
- **Cibles de sobriété** (point de la fiche, valeurs fixées après la première mesure et
  reportées au cahier des charges) **[à relire]** : 5 min de CPU et 1 Gio de mémoire au
  plus par scan, sur la machine de référence, pour un hôte d'environ 3 000 composants et
  150 000 fichiers.
- `modernc.org/sqlite` devient une dépendance directe (import de `hostagent`, déjà validé
  au § 5) ; nfpm ajouté en directive `tool` (validé).
- L'adresse du serveur de l'agent dépôt doit être en `https` (comme l'agent serveur).

### Écarts

- Numéro de migration : 011 attribué, devenu **009** (règle de l'orchestrateur : premier
  numéro libre et contigu, `main` à 008).
- « L'agent tourne sans root avec l'unité fournie » : pas de systemd dans l'environnement
  de réalisation ; vérifié par `systemd-analyze verify` et `security` (unités), et par
  `TestLeastPrivilege` (binaire réel sous `nobody`, `CAP_DAC_READ_SEARCH` seule, comme
  l'unité, via `setpriv`) : les bases de paquets réservées à root sont lues avec la
  capacité, pas sans. Un essai sur un hôte réel avec l'unité reste à faire en recette
  (T11).
- La mesure de « / » complet de la machine de développement dépasse les cibles (cache des
  modules Go) ; la cible porte sur une racine représentative d'un serveur (voir Mesures).
- Les paquets ne sont pas signés (T24, T26), comme prévu par la fiche.

### ADR créés

0020, 0021.

### Mesures

Machine de référence : 4 cœurs, 16 Gio, Ubuntu 24.04.5 (837 paquets deb), PostgreSQL
local ; binaire réel sous `nobody` avec `CAP_DAC_READ_SEARCH`, `max_procs` 1,
`memory_limit_mib` 512, contre un faux serveur HTTPS (`measure_test.go`).

| Racine | Cycle | Durée | CPU (utilisateur + système) | Mémoire maximale | Composants | SBOM (JSON / gzip) |
| --- | --- | --- | --- | --- | --- | --- |
| `/` sans `/root`, `/home`, `/tmp` (≈ 150 000 fichiers) | envoi | 2 min 53 s | 2 min 44 s | 850 Mio | 2 998 | 23,7 Mio / 3,5 Mio |
| idem | signal de vie | 3 min 22 s | 2 min 39 s | 899 Mio | 2 998 | — |
| `/` complet (≈ 530 000 fichiers, dont 384 000 du cache des modules Go) | envoi | 16 min 3 s | 14 min 37 s | 2 751 Mio | 4 541 | 44,1 Mio / 5,3 Mio |
| idem | signal de vie | 14 min 39 s | 13 min 13 s | 3 002 Mio | 4 541 | — |

- Cible (5 min de CPU, 1 Gio) **tenue** pour la racine représentative d'un serveur ; le
  second cycle confirme l'inventaire sans renvoyer les 3,5 Mio. Le coût est dominé par le
  parcours des fichiers par Syft (index de tous les chemins) et par la relecture du SBOM
  pour l'empreinte (environ trente fois sa taille, mesure de T05).
- `testdata/rootfs` : environ 2 s par scan (tests unitaires).
- **Binaires** (`CGO_ENABLED=0`, `-s -w`) : `ogsbom-host-agent` 83,6 Mo (amd64), 77,7 Mo
  (arm64) — Syft et tous ses fournisseurs de sources (images, archives) ; paquets deb et
  rpm 25,5 à 28,1 Mo. Pour comparaison, `ogsbom-server` 65,9 Mo, `ogsbom-repo-agent`
  84,2 Mo.
- Couverture : `agentclient` 91,1 %, `hostagent` 83,0 %, `agent` et `inventory` couverts
  par leurs tests d'intégration (nouveaux cas).

### Pour les lots suivants

- **T08 et suivants (agent dépôt)** : `repoagent.NewServer(cfg, token,
  ServerOptions{Version, Logger, Transport})` repose sur `agentclient` ; un test contre un
  serveur HTTP local passe un `Transport` (l'adresse `http` n'est admise qu'avec lui).
- **T11 (recette)** : installer un paquet sur un hôte réel (Debian ou Ubuntu, RHEL ou dérivée),
  activer l'unité, vérifier le scan sans root, le scan à la
  demande, le mTLS ; vérifier la note de `systemd-analyze security`.
- **T13 (conteneurs)** : les stockages de conteneurs sont exclus du scan de l'hôte
  (`DefaultExclusions`) ; les conteneurs deviendront des projets enfants avec leur propre
  référence ; `Inventory`, `Store` et le cycle peuvent être étendus par conteneur.
- **T15 (politiques)** : « agent muet depuis N jours » se lit sur `agent.Activity.Since`.
- **T22 (Windows)** : `uname_other.go` renvoie un contexte vide ; exclusions et
  `/proc/self/mountinfo` sont propres à Linux.
- **T23 (hors ligne)** : le cycle sépare déjà scan (`Scanner`) et envoi ; un mode qui
  écrit le SBOM dans un fichier se branche à la place de `send`.
