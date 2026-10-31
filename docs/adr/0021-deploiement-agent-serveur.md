# 0021 — Déploiement de l'agent serveur : moindre privilège, secrets, mTLS, paquets

- Statut : Accepté
- Date : 2026-10-31
- Lot : T07

## Contexte

L'agent tourne sur des serveurs de production. La fiche T07 fixe l'essentiel : utilisateur
dédié avec `CAP_DAC_READ_SEARCH`, unité systemd durcie, écriture limitée au répertoire
d'état, secrets en credentials systemd ou fichiers `0600`, mTLS facultatif, paquets deb et
rpm par nfpm. Restaient : la forme exacte des unités, la lecture des secrets, la place du
contrôle mTLS côté serveur et la façon de produire les paquets.

## Décision

- **Deux unités, une seule active** : `ogsbom-host-agent.service` (démon, recommandé :
  il reçoit les demandes de scan) et `ogsbom-host-agent-oneshot.service` lancée par
  `ogsbom-host-agent-oneshot.timer` (tous les jours à 2 h, `RandomizedDelaySec=1h`,
  `Persistent=true`) ; elles se déclarent en conflit. Le mode est posé par l'unité
  (`OGSBOM_HOST_AGENT_MODE`).
- **Durcissement** : `User=ogsbom-agent`, `AmbientCapabilities=` et
  `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices`, protections du noyau,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, filtre `@system-service`
  sans `@privileged`, `MemoryDenyWriteExecute`, `UMask=0077`, `StateDirectory` en `0700`.
  Note `systemd-analyze security` : 1,9 (« OK »). Sobriété : `Nice=19`,
  `IOSchedulingClass=idle`, `MemoryMax=1536M` (limite dure ; la limite douce est
  `GOMEMLIMIT`, `resources.memory_limit_mib`), `CPUQuota=` proposé en commentaire.
- **Secrets** : jamais dans `config.yaml`. Jeton d'inscription : `enrollment_token_file`,
  sinon le credential systemd `enrollment-token` (`LoadCredentialEncrypted=`), sinon
  `/etc/ogsbom-host-agent/enrollment-token` ; clé du certificat client :
  `server.client_key_file`, sinon le credential `client-key`. Hors du répertoire des
  credentials, un fichier secret accessible au groupe ou aux autres est **refusé**. Le
  jeton d'agent est écrit par l'agent dans son répertoire d'état (`0700`, fichier `0600`,
  écriture atomique) et n'expire pas (ADR 0014).
- **HTTPS seulement** : l'adresse du serveur doit être en `https://` ; autorité privée
  (`ca_file`, qui remplace celles du système), certificat client relu à chaud quand il
  change sur le disque, mandataire explicite ou de l'environnement ; aucune redirection
  suivie (le jeton ne part jamais ailleurs).
- **mTLS côté serveur** : le serveur TLS vérifie un certificat présenté
  (`VerifyClientCertIfGiven`, pour que l'interface reste accessible aux navigateurs) ; avec
  `tls.client_ca_file`, un middleware de l'API des agents refuse toute requête sans
  chaîne vérifiée (401 `error.client_cert_required`), avant toute lecture du jeton, par le
  limiteur des refus par IP. Le certificat n'est pas lié à l'identité de l'agent : il
  prouve l'appartenance au parc, le jeton identifie l'agent.
- **Paquets** : `make packages` construit l'agent pour amd64 et arm64 (`CGO_ENABLED=0`)
  et produit avec nfpm (directive `tool`, v2.48.0) quatre paquets non signés : binaire,
  configuration (`config|noreplace`), unités, `sysusers.d`. Le script d'installation crée
  l'utilisateur (`systemd-sysusers`, sinon `useradd`) et rend `/etc/ogsbom-host-agent`
  lisible du seul groupe de l'agent ; aucune unité n'est activée d'office. La
  désinstallation arrête les unités, sauf lors d'une mise à jour, et garde l'état.
  `make packages` fait partie de `make ci`.

## Conséquences

- `CAP_DAC_READ_SEARCH` donne la lecture et le parcours de tout fichier, pas l'écriture :
  l'agent voit autant que root en lecture, d'où le durcissement de l'unité et l'absence de
  toute autre sortie que le SBOM et le contexte de l'hôte.
- Derrière un mandataire inverse qui termine TLS, le mTLS n'est pas disponible (déjà
  refusé par la validation de la configuration, § 6).
- Les paquets ne sont pas signés avant T24 et T26 ; leurs sommes de contrôle sont à
  publier avec eux.

## Alternatives écartées

- **Agent root** : plus simple, mais contraire au cahier des charges ; la capacité suffit
  à lire les bases de paquets (vérifié par `TestLeastPrivilege`).
- **Credential systemd obligatoire** (`LoadCredentialEncrypted=` dans l'unité livrée) :
  l'unité échouerait sans le fichier ; `ImportCredential=` (systemd 254) n'existe pas
  sur RHEL 9. Le credential reste proposé en commentaire.
- **`RequireAndVerifyClientCert` au niveau TLS** : refuserait aussi les navigateurs de
  l'interface servie par la même écoute.
- **Certificat client lié à l'agent** (nom d'hôte dans le CN) : demanderait une PKI par
  hôte alignée sur les inscriptions ; laissé à une évolution si un besoin apparaît.
