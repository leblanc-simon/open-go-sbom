# T08 — Agent dépôt sans IA et forges

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T05 | Terminé |

## Objectif

`ogsbom-repo-agent` : un service externe aux CI qui détient seul les accès aux forges, réagit
aux push, clone le commit visé, l'analyse avec Syft et envoie le SBOM. L'enrichissement IA
viendra se greffer en T12 sans changer ce pipeline.

## Périmètre

**Inclus**

- `internal/forge` : interface `Provider` (accès en lecture, vérification d'un webhook,
  résolution d'une référence en commit, liste des fichiers modifiés entre deux commits ;
  publication de statut en T15) et deux implémentations : GitHub App, et GitLab par compte
  de service.
- `internal/repoagent` : liste des dépôts et du dernier commit analysé par référence depuis
  `GET /api/v1/agent/projects`, récepteur de webhooks, planificateur de rattrapage, file en
  mémoire bornée et dédoublonnée, clonage, scan Syft du répertoire, encodage CycloneDX avec
  `ogsbom:origin=syft`, envoi, nettoyage.
- Configuration : serveur, forges, répertoire de travail, parallélisme, délais, taille
  maximale. Secrets (jeton d'agent, clé privée de la GitHub App, jetons des comptes de
  service, secrets de webhook) fournis par credentials systemd chiffrés ou fichiers `0600`,
  jamais dans le fichier de configuration.
- Mode d'exploitation documenté : une instance d'agent par organisation, son URL de webhook
  publique, les droits minimaux par forge.

**Exclu** : enrichissement IA (T12), statut de commit (T15), compatibilité
Dependency-Track (T19).

## Conception

- GitHub App : JWT RS256 signé en stdlib, jeton d'installation mis en cache jusqu'à
  expiration ; webhook vérifié par `X-Hub-Signature-256`. GitLab : secret
  `X-Gitlab-Token` comparé en temps constant.
- Pas de file durable côté agent : au démarrage puis à intervalle, le planificateur compare
  le commit de tête de chaque référence au dernier commit connu du serveur et rattrape les
  écarts.
- Clonage par le binaire `git`, avec un environnement maîtrisé :
  `--depth 1 --single-branch --no-tags` puis vérification du commit exact ;
  `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, hooks
  désactivés, `core.symlinks=false` (aucun lien symbolique sur disque), LFS désactivé ;
  identifiants passés par `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`, jamais
  dans l'URL ni dans les arguments du processus.
- Un répertoire de travail par analyse, supprimé à la fin quoi qu'il arrive ; taille du
  clone et durée bornées ; aucun fichier du dépôt n'est exécuté.
- Le récepteur de webhooks est exposé à Internet : signature obligatoire, taille de corps
  bornée, limitation de débit, réponse immédiate et traitement asynchrone.

## Livrables

Binaire, `config.example.yaml`, section « Agent dépôt » de `docs/operations.md` (création de
la GitHub App et des comptes de service, droits minimaux, credentials systemd).

## Critères d'acceptation

- [x] Un push signé sur une référence suivie produit un instantané pour ce commit.
- [x] Un webhook mal signé est refusé et journalisé sans contenu.
- [x] Un redémarrage de l'agent rattrape les commits manqués.
- [x] Les identifiants n'apparaissent ni dans les arguments des processus (`ps`), ni dans
      les journaux, ni en clair dans le fichier de configuration.
- [x] Un lien symbolique du dépôt pointant hors de l'arborescence est extrait comme simple
      fichier et n'est pas suivi par le scan.
- [x] Un dépôt trop gros ou trop long à cloner échoue proprement, sans fichier résiduel.
- [x] Droits minimaux documentés et vérifiés pour chaque forge (voir Écarts pour la part
      vérifiable sans forge réelle).

## Tests attendus

Unitaires : vérification des webhooks (valides, invalides, rejoués), JWT GitHub, file.
Intégration : forges simulées (`httptest`), dépôt nu local créé par le test (avec liens
symboliques piégés), serveur de test ; pipeline complet.

## Décisions

Prises le 31 octobre 2026 :

- Forges du lot 1 : GitHub (GitHub App) et GitLab (compte de service). Forgejo est
  reporté : l'interface `Provider` l'accueillera sans changer le pipeline, quand le besoin
  se présentera.

## Journal

Réalisé le 31 octobre 2026, branche `lot/T08-agent-depot`, en parallèle de T06 et T07.

### Livré

- `internal/forge` : interface `Provider` (`Repo` depuis l'URL de forge d'un projet,
  `CloneURL`, `Credentials`, `ResolveRef`, `Compare`, `VerifyWebhook`), types `Ref`,
  `Push`, `Comparison`, `Credentials` (masqués à l'affichage), erreurs `ErrSignature`,
  `ErrPayload`, `ErrNotFound`, `ErrDenied`.
  - **GitHub App** : JWT RS256 en bibliothèque standard (`ParseRSAPrivateKey` PKCS #1 et
    #8), installation cherchée par dépôt ou fixée, jeton d'installation **restreint à
    `contents: read`** et mis en cache jusqu'à cinq minutes de son expiration, webhook
    vérifié par `X-Hub-Signature-256` (HMAC en temps constant), github.com et GitHub
    Enterprise Server.
  - **GitLab** par compte de service : `PRIVATE-TOKEN`, chemins de projet encodés,
    sous-groupes et instance sous un sous-chemin, `X-Gitlab-Token` comparé en temps
    constant, événements `Push Hook` et `Tag Push Hook`.
- `internal/repoagent` :
  - catalogue des dépôts confiés (toutes les pages de `listAgentProjects`), signal de vie,
    rattrapage au démarrage, à `catchup.interval` et sur webhook d'un dépôt inconnu ;
  - récepteur de webhooks `POST /webhooks/<forge>` et `GET /healthz` : corps borné,
    débit limité par IP (`ratelimit` d'open-go-base), signature obligatoire avant toute
    lecture, livraisons rejouées écartées, 202 immédiat ;
  - file en mémoire bornée, dédoublonnée, sans traitement simultané d'une même référence ;
  - extraction d'un commit exact par `git` sous environnement maîtrisé, taille mesurée
    pendant le clonage, délais, groupe de processus tué à l'annulation, `.git` supprimé,
    parcours par `os.Root` contre tout lien symbolique, répertoire d'analyse supprimé
    quoi qu'il arrive et nettoyé au démarrage ;
  - scan Syft (source `dir` bornée, catalogueurs hors ligne et sans exécution, pilote
    SQLite importé), encodage CycloneDX 1.6 déterministe avec `ogsbom:origin=syft` ;
  - envoi multipart (`context` puis `sbom` gzip), interface locale `Server` ;
  - configuration (`OGSBOM_REPO_*`, forges en YAML), secrets par `credential:<nom>` ou
    fichier `0600`/`0400` (`ReadSecret`), validation complète.
- `cmd/ogsbom-repo-agent` : câblage, TLS natif facultatif du récepteur, arrêt propre sur
  SIGTERM (récepteur, puis clonages tués et répertoires supprimés).
- `deploy/ogsbom-repo-agent/` : `config.example.yaml` commenté (chargé et validé par un
  test) et unité systemd durcie (`DynamicUser`, `LoadCredentialEncrypted=`,
  `ProtectSystem=strict`, aucune capacité, `ProtectProc=invisible`…).
- Tests : unitaires (webhooks valides, mal signés, rejoués, illisibles, ignorés ; JWT et
  clés ; jetons d'installation et cache ; API simulées des deux forges ; file ; secrets ;
  configuration ; récepteur, débit et taille ; client de l'API) ; intégration
  (`integration`) : dépôt nu créé par le test avec trois liens symboliques piégés
  (`/etc/passwd`, répertoire extérieur, chemin relatif sortant), GitHub simulée par
  `httptest` (API + `git http-backend` en CGI exigeant le jeton d'installation),
  pipeline complet (rattrapage ordonné, push signé, mal signé, rejoué, push d'un commit
  dépassé), git enveloppé qui note ses arguments, dépôt trop gros, clonage trop long ;
  **bout en bout contre le vrai serveur** (`internal/web/repoagent_integration_test.go` :
  base jetable, agent et projet réels, ingestion décodée, instantané par commit, push mal
  signé, redémarrage).
- ADR 0023 ; `architecture.md` (§ 17) ; `docs/operations.md` (« Agent dépôt » : mode
  d'exploitation, GitHub App, compte de service GitLab, droits minimaux, credentials
  systemd) ; modèle de menace.

### Décisions

- **ADR 0023** **[à relire]**, notamment :
  - **un webhook n'est qu'un signal** : la tête de la référence est résolue auprès de la
    forge ; le commit annoncé n'est jamais analysé tel quel (un webhook rejoué ne peut pas
    rendre courant un commit dépassé, GitHub ne signant pas d'horodatage) ;
  - **extraction par `git fetch --depth 1 <url> <commit>`** plutôt que
    `clone --single-branch` (écart à la fiche, voir Écarts) ;
  - **SBOM déterministe** : ni `serialNumber` ni `metadata.timestamp`, composant décrit =
    slug du projet à ce commit ; un renvoi du même commit vaut 200 côté serveur ;
  - **`golang.UsePackagesLib=false`** et catalogueurs sans réseau : Syft lance sinon
    `go list` sur le dépôt ;
  - base de comparaison = dernier commit envoyé par l'instance, sinon celui du serveur ;
    `catchup.max_commits` (20) plus récents ; tête seule pour une étiquette, une première
    analyse ou une comparaison impossible ;
  - échecs définitifs (trop gros, lien symbolique, refus 4xx du serveur) non retentés
    avant redémarrage ; délais et erreurs réseau retentés au passage suivant ;
  - secrets désignés par `credential:<nom>` ou chemin absolu d'un fichier sans droit pour
    le groupe ni les autres.
- **Valeurs par défaut** **[à relire]** : parallélisme 2, file 1 000, clonage 10 min et
  1 024 Mio, scan 15 min, rattrapage 15 min et 20 commits, corps de webhook 1 Mio,
  120 webhooks par minute et par IP, requête au serveur 2 min, appel de forge 30 s.
- Jeton GitLab présenté à git avec l'utilisateur `oauth2` ; jeton GitHub avec
  `x-access-token` ; identifiants dans `http.extraHeader` (en-tête `Authorization:
  Basic`) passé par `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`.
- Le récepteur répond 503 si la file est pleine (la forge le signale, le rattrapage
  refera le travail) et 204 à un événement authentique sans intérêt (ping).
- Configuration et unité systemd sous `deploy/ogsbom-repo-agent/` (pas à la racine, où
  `config.example.yaml` est celui du serveur).
- Pas de suivi de l'état des ingestions (`getIngestion`) dans ce lot : le serveur range
  par date de scan, l'ordre d'envoi suffit ; T15 l'ajoutera pour publier le verdict.

### Écarts

- **Clonage** : `git fetch --depth 1 --no-tags` du commit au lieu de
  `git clone --depth 1 --single-branch --no-tags` (fiche) : un clone de branche ne
  contient pas les commits anciens à rattraper (ADR 0023).
- **`os.Root`** (§ 17) : git écrit l'arborescence et Syft la lit par son propre
  résolveur, borné à sa racine (`WithBasePath`) ; `os.Root` sert au parcours qui vérifie
  qu'aucun lien symbolique n'existe (`core.symlinks=false` les écrit en fichiers). Rien
  ne peut donc sortir de l'arborescence ; § 17 précisé.
- **Identifiants et `ps`** : absents des arguments (vérifié en enveloppant git) et de
  l'URL ; l'en-tête encodé est dans l'environnement de git, lisible du seul compte de
  l'agent (`/proc/<pid>/environ`), et masqué aux autres par `ProtectProc=invisible`.
- **Droits minimaux vérifiés** : par test, le jeton GitHub demandé ne porte que
  `contents: read` et l'agent n'appelle que des lectures ; les portées GitLab
  (`read_api`, `read_repository`) et le refus d'un dépôt hors installation ne se
  vérifient qu'avec une forge réelle : procédure de vérification documentée dans
  `docs/operations.md` **[à relire]**.
- Le graphe de modules gagne les dépendances indirectes des fournisseurs de sources de
  Syft (`syft.GetSource`) ; `modernc.org/sqlite` passe en direct (validé § 5).

### ADR créés

0023.

### Mesures

- Couverture (unitaires et intégration) : `forge` 93,4 %, `repoagent` 92,1 %.
- Scan Syft d'un petit dépôt (go.mod, requirements.txt) : environ 4 s, surtout
  l'initialisation des catalogueurs ; création du dépôt de test et trois extractions de commit
  (dont deux en échec attendu) : 0,19 s au total.
- Binaire `ogsbom-repo-agent` (linux/amd64, `-trimpath -s -w`) : 83,5 Mo (79,7 Mio), dont
  Syft et ses fournisseurs de sources ; pour comparaison, `ogsbom-server` 65,9 Mo.

### Pour les lots suivants

- Client de l'API : `repoagent.NewServer` repose depuis T07 sur le client commun
  d'`internal/agentclient` (réessais bornés, `Retry-After`, autorité privée, mTLS par
  `server.client_cert_file` et `server.client_key_file`, mandataire) ; un refus 4xx hors 429
  enveloppe `repoagent.ErrRejected`. L'adaptateur provisoire `APIServer` a disparu.

- **T12 (IA)** : le pipeline produit le SBOM Syft dans `scanner.scan` ; l'enrichissement
  se greffe entre le scan et l'envoi, sur l'arborescence extraite (avant sa suppression),
  et ajoute ses composants avec `ogsbom:origin=ia`. `forge.Comparison.Files` donne les
  fichiers modifiés.
- **T15 (statut de commit)** : ajouter au `Provider` la publication de statut ; droit
  GitHub *Commit statuses: write* (le jeton reste restreint par `permissions`), portée
  GitLab `api` ; suivre l'ingestion par `getIngestion` pour obtenir le verdict.
- **Forgejo** : une implémentation de `forge.Provider` de plus, sans toucher au pipeline.
