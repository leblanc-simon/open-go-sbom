# Échantillon pilote annoté de l'enrichissement IA

Les quatre dépôts publics du parc pilote du lot 1 (recette de T11), annotés à la main pour
la recette du lot 2 (T18) : l'évaluation de l'enrichissement IA se mesure sur le corpus
synthétique ([`../ai-corpus/`](../ai-corpus/README.md)) **et** sur cet échantillon, avec les
mêmes seuils (taux de faux positifs ≤ 5 %, rappel ≥ 80 %, décision du 1er novembre 2026).

Le contenu des dépôts n'est pas recopié ici (taille, licences) : chaque `expected.yaml`
désigne le dépôt et le commit (`source`), et `scripts/ai-pilot-fetch.sh <répertoire>` les
clone et les extrait à ce commit (le script vérifie la tête). Les champs sont ceux du
corpus (`components`, `forbidden`, `ignored`, voir son README), plus `source`.

| Cas | Dépôt, commit | Composants attendus |
| --- | --- | --- |
| `cobra` | GitHub `spf13/cobra`, `adbc881` (10 juillet 2026) | aucun : `go.mod` et flux GitHub Actions, lus par Syft |
| `sftp` | GitHub `pkg/sftp`, `5bdc2b0` (20 novembre 2023) | aucun : `go.mod` et flux GitHub Actions |
| `gitlab-shell` | GitLab `gitlab-org/gitlab-shell`, `09ef3a7` (18 décembre 2023) | 4 : gotestsum 1.10.0 et golangci-lint 1.55.2 (variables du `Makefile`, téléchargés par `curl`), images `docker:20.10.15` (variable de `.gitlab-ci.yml`) et `sourcegraph/lsif-go:v1.9` |
| `jekyll` | GitLab `pages/jekyll`, `3137780` (30 avril 2025) | aucun : `Gemfile.lock`, image `ruby:latest` |

## Règles d'annotation

Établies le 1er novembre 2026 en lisant chaque fichier de chaque dépôt hors code Go, Ruby
de test et données de test, puis en confrontant au SBOM de Syft (même version que l'agent,
catalogueurs hors ligne) :

- **composant attendu** : composant tiers effectivement utilisé (livré, image de base ou de
  l'intégration continue, outil téléchargé par la construction) dont le nom et la version
  exacte sont écrits sur une ligne du dépôt, et qu'aucun manifeste lu par Syft ne
  déclare ; purl au type le plus précis (règle 3 du prompt) ;
- **ignoré** (ni juste ni faux) : ce que Syft voit déjà (actions GitHub des flux de
  travail : la fusion les écarte, Syft l'emportant), et les cas discutables (chaîne
  d'outils de `.tool-versions`, image au nom formé de variables, service `-dind` dont la
  version n'est sur aucune ligne) ;
- **piège** (`forbidden`) : version du dépôt lui-même, étiquette `latest`, composant
  déclaré dans un manifeste ;
- tout autre composant accepté est un faux positif.

L'échantillon est petit (4 composants attendus) : un rappel s'y lit au composant près, et un
seul faux positif y dépasse vite 5 %. C'est voulu : il dit ce que l'enrichissement ajoute
réellement à des dépôts ordinaires, où presque tout est déjà déclaré.

## Usage

```bash
scripts/ai-pilot-fetch.sh /tmp/lotor-ai-pilot
LOTOR_EVAL_AI_PILOT_DIR=/tmp/lotor-ai-pilot LOTOR_EVAL_AI_PROVIDER=anthropic \
  LOTOR_EVAL_AI_API_KEY_FILE=… make eval-ai
```

Sans clé ni modèle, `LOTOR_EVAL_AI_PROVIDER=credulous` joue un modèle fictif qui soumet
tout ce qu'il trouve : il vérifie que chaque annotation est prouvable et qu'aucun composant
n'est accepté sans preuve vérifiée ; ce n'est pas une mesure de qualité (procédure
complète : `docs/operations.md`, « Évaluer l'enrichissement IA »).
