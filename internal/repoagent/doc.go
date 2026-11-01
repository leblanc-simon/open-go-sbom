// Package repoagent porte le pipeline de l'agent dépôt : forges, clonage, Syft,
// enrichissement IA et envoi.
//
// Enrichissement IA (T12, ADR 0042 à 0044). Après le scan de Syft, si le réglage du projet
// transmis par le serveur le permet (AIMode) et qu'un modèle est configuré (AIConfig), un
// modèle explore l'arborescence extraite par quatre outils : list_dir, read_file et search
// en lecture seule, confinés par un os.Root au répertoire de l'analyse et aveugles aux
// fichiers exclus (DefaultExclude, AIConfig.Exclude, clés privées détectées dans le
// contenu), puis submit_candidates, validé par un schéma JSON. Le vérificateur (verify) est
// seul juge : il relit chaque preuve dans le fichier au commit analysé (extrait à la ligne
// annoncée à trois lignes près, nom et version présents, purl valide et cohérent avec le
// fichier, ni documentation, ni manifeste déjà lu par Syft, ni fichier qui s'adresse au
// modèle). Les composants acceptés rejoignent le SBOM avec lotor:origin=ia,
// lotor:confidence, lotor:model et le champ evidence ; Syft l'emporte en cas de doublon.
// Le statut de l'enrichissement (complete, incomplete, carried) est écrit dans les
// métadonnées (lotor:enrichment) : budget dépassé ou erreur du fournisseur → SBOM Syft
// seul, marqué incomplet. L'analyse est incrémentale (fichiers modifiés selon la forge,
// composants IA précédents revérifiés), complète à AIConfig.FullInterval ; le prompt
// système est versionné et embarqué (prompts/, PromptVersion).
//
// Corpus d'évaluation annoté : testdata/ai-corpus (tests déterministes avec un faux
// fournisseur ; mesure avec un vrai modèle par make eval-ai).
package repoagent
