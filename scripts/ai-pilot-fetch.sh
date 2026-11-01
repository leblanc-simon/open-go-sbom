#!/bin/sh
# Prépare l'échantillon pilote de l'évaluation de l'enrichissement IA
# (testdata/ai-pilot/README.md) : clone chaque dépôt public annoté et l'extrait au commit
# de son annotation. Usage : scripts/ai-pilot-fetch.sh <répertoire>
# Puis : LOTOR_EVAL_AI_PILOT_DIR=<répertoire> make eval-ai (docs/operations.md).
set -eu

dest=${1:?usage : scripts/ai-pilot-fetch.sh <répertoire>}
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$dest"

for annotation in "$root"/testdata/ai-pilot/*/expected.yaml; do
	name=$(basename "$(dirname "$annotation")")
	url=$(sed -n 's/^  url: *//p' "$annotation")
	commit=$(sed -n 's/^  commit: *//p' "$annotation")
	if [ -z "$url" ] || [ -z "$commit" ]; then
		echo "$annotation : source.url ou source.commit manquant" >&2
		exit 1
	fi
	dir="$dest/$name"
	if [ ! -d "$dir/.git" ]; then
		git clone --quiet --filter=blob:none --no-checkout "$url" "$dir"
	fi
	git -C "$dir" -c advice.detachedHead=false checkout --quiet --force --detach "$commit"
	head=$(git -C "$dir" rev-parse HEAD)
	if [ "$head" != "$commit" ]; then
		echo "$name : HEAD $head au lieu de $commit" >&2
		exit 1
	fi
	echo "$name : $commit"
done
