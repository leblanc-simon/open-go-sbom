# 0042 — Fournisseurs de modèles : SDK Go officiel d'Anthropic sans environnement, Ollama par HTTP

- Statut : Accepté (décision prise en autonomie le 1er novembre 2026, **à relire**)
- Date : 2026-11-01
- Lot : T12

## Contexte

L'enrichissement IA de l'agent dépôt appelle un modèle en boucle d'outils. Le § 5 de
l'architecture prévoyait « SDK Go officiel d'Anthropic ; Ollama par son API HTTP sans
SDK », statut « à valider en T12 ». La consigne du lot 2 est de valider soi-même toute
dépendance, avec la qualité pour premier critère, en préférant la bibliothèque standard
et ce qui est déjà dans le graphe, et de justifier un éventuel client HTTP maison.

Contraintes propres à l'agent dépôt :

- rien d'autre que le prompt système et le contenu des fichiers lus ne doit partir vers
  le fournisseur, et la clé d'API reste un secret de l'agent (credential systemd ou
  fichier 0600) ;
- l'agent est un binaire léger : `internal/llm` ne dépend d'aucun paquet serveur (§ 4) ;
- les réponses du modèle sont des données non fiables.

Constats sur `github.com/anthropics/anthropic-sdk-go/v2` v2.4.0 (27 octobre 2026, dernière
version publiée) :

- il couvre l'API Messages et ses évolutions (blocs de raisonnement à renvoyer inchangés,
  raisons d'arrêt `refusal`, en-tête de version d'API, réessais 429/5xx avec
  `retry-after`) : un client maison devrait suivre ces changements à la main ;
- `anthropic.NewClient()` lit par défaut l'environnement (`ANTHROPIC_API_KEY`,
  `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`, profils sur
  disque, fédération d'identité) ; l'option `option.WithoutEnvironmentDefaults()`
  désactive toute cette lecture ;
- son ajout à `go.mod` ne tire que six lignes nouvelles (le SDK, `tidwall/gjson`,
  `tidwall/sjson`, `tidwall/match`, `tidwall/pretty`, `standard-webhooks`) : le reste
  (OpenTelemetry, `invopop/jsonschema`…) est déjà dans le graphe de Syft ; les
  sous-paquets Bedrock, Vertex et MCP ne sont pas importés et n'entrent pas dans le
  binaire.

## Décision

1. **Anthropic par le SDK Go officiel**, `github.com/anthropics/anthropic-sdk-go/v2`,
   version épinglée v2.4.0, importé par le seul `internal/llm`.
2. **Client construit sans environnement** : `option.WithoutEnvironmentDefaults()`, puis
   clé, adresse (`ai.external.base_url`, https exigé), client HTTP, délai et nombre de
   réessais venus de la configuration de l'agent. Une variable `ANTHROPIC_*` posée sur la
   machine ne change ni la destination, ni la clé, ni les en-têtes (testé).
3. **Requête minimale** : modèle, `max_tokens`, prompt système (marqué pour le cache de
   prompt, identique d'un tour à l'autre), outils, messages. Ni température, ni réglage du
   raisonnement, ni choix d'outil forcé (refusé par `claude-sonnet-5-5`) : l'appel de
   `submit_candidates` est demandé par le prompt et vérifié par l'agent. Les réponses
   sont renvoyées telles quelles aux tours suivants (`Message.Opaque`), blocs de
   raisonnement compris, comme l'API l'exige.
4. **Pas de repli de modèle côté serveur** (`fallbacks`, bêta) : un refus
   (`stop_reason: refusal`) termine l'analyse en « enrichissement incomplet » ; le modèle
   attribué à chaque composant (`lotor:model`) reste celui que l'exploitant a choisi.
5. **Erreurs résumées** par statut et type (`anthropic : statut 429 (rate_limit_error)`) :
   ni corps de réponse, ni requête dans les journaux.
6. **Ollama par son API HTTP** (`POST /api/chat`, sans flux), en bibliothèque standard :
   réponse bornée à 8 Mio, identifiants d'appel d'outil synthétisés quand Ollama n'en
   donne pas, fenêtre de contexte (`num_ctx`) configurable. Le modèle est attribué
   `ollama/<modèle>`.
7. Une interface `llm.Provider` commune (`Model`, `External`, `Complete`) et une boucle
   `llm.Run` (budget de tours et de jetons, outil inconnu refusé, une seule relance si le
   modèle rend la main sans soumettre) : changer de fournisseur ne touche pas la logique
   de l'agent. `External()` sert la règle d'envoi de code (ADR 0043) : un modèle
   « local » qui se déclarerait externe, ou l'inverse, est refusé au démarrage.

## Conséquences

- Les évolutions de l'API Messages arrivent par une montée du SDK (une montée de version
  ne demande pas de nouvelle validation, § 5) ; `govulncheck` couvre le SDK.
- Le binaire `lotor-repo-agent` grossit du SDK et de `gjson`/`sjson`.
- Le coût d'une analyse dépend du cache de prompt : la consommation rapportée sépare les
  jetons lus et écrits dans le cache (`llm.Usage`), et l'évaluation les tarife à part.
- Le SDK et Ollama sont éprouvés par des serveurs `httptest` (forme de la requête,
  renvoi des blocs de raisonnement, raisons d'arrêt, erreurs, environnement ignoré) ; un
  appel réel n'a lieu que dans `make eval-ai`.

## Alternatives écartées

- **Client HTTP maison pour Anthropic** : quelques centaines de lignes pour la seule API
  Messages, mais à maintenir à chaque évolution (blocs de raisonnement liés au modèle,
  versions d'API, sémantique des réessais) ; le contrôle de ce qui part, son seul
  avantage, s'obtient avec le SDK par `WithoutEnvironmentDefaults` et une requête
  construite champ par champ.
- **SDK construit par défaut** (`anthropic.NewClient()`) : une variable d'environnement
  ou un profil sur disque pourrait rediriger le code vers une autre adresse ou une autre
  clé, hors de la configuration revue par l'exploitant.
- **Bibliothèque d'abstraction multi-fournisseurs** (langchaingo, etc.) : dépendances
  nombreuses, comportement réseau moins lisible, sans besoin au-delà de deux
  fournisseurs.
- **Client Ollama officiel** (`github.com/ollama/ollama/api`) : tire le module Ollama
  entier pour un seul point d'accès JSON.
- **Repli automatique vers un autre modèle sur refus** : coût et attribution moins
  prévisibles ; le repli de lotor est le SBOM Syft seul.
