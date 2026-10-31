# T08 — Agent dépôt sans IA et forges

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T05 | À faire |

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

- [ ] Un push signé sur une référence suivie produit un instantané pour ce commit.
- [ ] Un webhook mal signé est refusé et journalisé sans contenu.
- [ ] Un redémarrage de l'agent rattrape les commits manqués.
- [ ] Les identifiants n'apparaissent ni dans les arguments des processus (`ps`), ni dans
      les journaux, ni en clair dans le fichier de configuration.
- [ ] Un lien symbolique du dépôt pointant hors de l'arborescence est extrait comme simple
      fichier et n'est pas suivi par le scan.
- [ ] Un dépôt trop gros ou trop long à cloner échoue proprement, sans fichier résiduel.
- [ ] Droits minimaux documentés et vérifiés pour chaque forge.

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

_À remplir pendant la réalisation._
