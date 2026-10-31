# T12 — Enrichissement IA de l'agent dépôt

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | À faire |

## Objectif

Compléter le SBOM Syft d'un dépôt par les composants que les manifestes ne déclarent pas,
sans jamais accepter un composant dont la preuve n'a pas été vérifiée de façon
déterministe, et avec un taux de faux positifs mesuré.

## Périmètre

**Inclus**

- `internal/llm` : interface `Provider` (boucle d'appels d'outils, budget, arrêt) ;
  implémentations Anthropic (SDK Go officiel) et Ollama (API HTTP).
- Boucle d'analyse dans `internal/repoagent` : outils en lecture seule `list_dir`,
  `read_file` (plage de lignes, taille bornée), `search` (expression, motif de fichiers,
  résultats bornés), et `submit_candidates` (sortie au schéma imposé). Tous les accès aux
  fichiers passent par un `os.Root` ouvert sur le répertoire de travail de l'analyse.
- Vérificateur déterministe des candidats, fusion avec Syft, encodage CycloneDX avec
  `evidence`, `ogs:origin=ia`, `ogs:confidence`, `ogs:model`.
- Analyse incrémentale : fichiers modifiés depuis le dernier commit analysé, obtenus par
  l'API de comparaison de la forge (le clone superficiel n'a pas d'historique), plus les
  fichiers des composants IA de l'instantané précédent, lus par une nouvelle route
  `GET /api/v1/agent/refs/{id}/ai-components` ; analyse complète à intervalle configurable.
- Exclusion des fichiers sensibles (motifs configurables, détection de clés privées) avant
  tout envoi au modèle.
- Réglage par projet : IA désactivée, modèle local uniquement, ou fournisseur externe.
- Serveur : bloc « preuve » sur la fiche composant (fichier, ligne, extrait, confiance,
  modèle), filtre par origine, compte par origine sur la fiche projet.
- Corpus d'évaluation **annoté** `testdata/ai-corpus/` : petits dépôts synthétiques au
  contenu connu (bibliothèque JS minifiée recopiée, `FROM` de Dockerfile, script chargé
  depuis un CDN, outil installé par `curl | sh`), pièges à faux positifs (version citée
  dans un commentaire, nom homonyme), et dépôts hostiles (instructions malveillantes dans
  un README ou des commentaires).

**Exclu** : changement du socle Syft ou de l'envoi (T08).

## Conception

- Vérificateur, seul juge de l'acceptation : relit le fichier au commit analysé, vérifie que
  l'extrait figure à la ligne annoncée (tolérance de quelques lignes), que le nom et la
  version y apparaissent après normalisation, que le purl proposé est syntaxiquement valide
  et cohérent avec le fichier. Tout échec rejette le candidat et compte le motif.
- Le vérificateur garantit qu'une preuve existe, pas que le composant est juste : la
  qualité se mesure donc sur le corpus annoté (précision et rappel).
- Fusion : dédoublonnage par `purl_base` et version ; en cas de conflit, Syft l'emporte.
- Le contenu du dépôt est une donnée non fiable : les sorties d'outils sont présentées au
  modèle comme des données, la seule sortie acceptée est l'appel `submit_candidates` validé
  par schéma, aucun outil n'écrit ni n'accède au réseau, le prompt système est versionné et
  embarqué.
- Seules sorties possibles vers le fournisseur : le prompt système et le contenu des fichiers
  lus dans l'arborescence de l'analyse en cours, hors fichiers exclus. Rien d'autre (fichiers
  d'autres analyses, secrets de l'agent, environnement) n'est accessible aux outils.
- ADR : séparation des privilèges (analyse et appels au modèle dans un processus fils sans
  accès aux secrets des forges) ou confinement par `os.Root` seul.
- Budget : nombre maximal de tours, de jetons et d'octets lus ; au-delà, l'analyse s'arrête
  et l'agent envoie le SBOM Syft seul, marqué « enrichissement incomplet ». Toute erreur du
  fournisseur → même repli.

## Livrables

Paquets, prompt système versionné, corpus annoté, rapport d'évaluation (précision, rappel,
taux de faux positifs, coût moyen par analyse) consigné dans le Journal, documentation des
réglages et de la politique d'envoi de code, ADR de séparation des privilèges.

## Critères d'acceptation

- [ ] Aucun composant accepté sans preuve vérifiée (garanti par construction, testé).
- [ ] Taux de faux positifs parmi les composants IA acceptés inférieur au seuil validé, sur
      le corpus annoté ; rappel supérieur au seuil validé.
- [ ] Un candidat inventé (version absente du fichier) est rejeté.
- [ ] Sur les dépôts hostiles : aucun fichier hors de l'arborescence de l'analyse, aucun
      fichier exclu, aucun secret de l'agent n'apparaît dans les échanges enregistrés par un
      faux fournisseur ; aucun composant non prouvé n'est accepté.
- [ ] Un projet réglé « IA désactivée » n'appelle jamais de modèle.

## Tests attendus

Faux `Provider` scénarisé et enregistreur pour les tests déterministes ; tests du
vérificateur en table ; évaluation sur le corpus avec un vrai modèle, hors CI par défaut
(cible `make eval-ai`).

## Points à trancher

- Fournisseur et modèle par défaut, et règle d'envoi de code à un modèle externe.
- Seuils de faux positifs et de rappel sur le corpus.

## Journal

_À remplir pendant la réalisation._
