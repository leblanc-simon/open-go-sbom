# T07 — Agent serveur Linux

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T05 | À faire |

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

- [ ] Sur un système de fichiers d'exemple (`testdata/rootfs`), le SBOM contient les paquets
      dpkg, rpm, apk et Python attendus, et rien sous les répertoires de conteneurs.
- [ ] Deux scans sans changement : un seul envoi, puis des signaux de vie.
- [ ] Le bouton « Scanner maintenant » déclenche un scan au prochain signal de vie.
- [ ] L'agent tourne sans root avec l'unité fournie et lit les bases de paquets.
- [ ] Avec `tls.client_ca` configuré, un agent sans certificat client valide est refusé.
- [ ] Temps CPU, durée et mémoire maximale d'un scan mesurés sur la machine de référence,
      consignés, et comparés à la cible validée (voir point à trancher).
- [ ] Taille des binaires consignée.

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

_À remplir pendant la réalisation._
