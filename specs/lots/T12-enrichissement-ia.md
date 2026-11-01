# T12 — Enrichissement IA de l'agent dépôt

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T16 | Terminé (mesure avec un vrai modèle à faire par l'utilisateur) |

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
  `evidence`, `lotor:origin=ia`, `lotor:confidence`, `lotor:model`.
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

## Maquettes

Planches « 7 · Fiche composant (origine IA) » du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj).

## Critères d'acceptation

- [x] Aucun composant accepté sans preuve vérifiée (garanti par construction, testé).
- [ ] Taux de faux positifs parmi les composants IA acceptés inférieur au seuil validé, sur
      le corpus annoté ; rappel supérieur au seuil validé. **Non mesuré** : aucune clé
      d'API dans l'environnement de réalisation ; corpus, faux fournisseur, harnais et cible
      `make eval-ai` livrés, mesure à faire par l'utilisateur, reprise par T18 (voir
      Écarts).
- [x] Un candidat inventé (version absente du fichier) est rejeté.
- [x] Sur les dépôts hostiles : aucun fichier hors de l'arborescence de l'analyse, aucun
      fichier exclu, aucun secret de l'agent n'apparaît dans les échanges enregistrés par un
      faux fournisseur ; aucun composant non prouvé n'est accepté.
- [x] Un projet réglé « IA désactivée » n'appelle jamais de modèle.

## Tests attendus

Faux `Provider` scénarisé et enregistreur pour les tests déterministes ; tests du
vérificateur en table ; évaluation sur le corpus avec un vrai modèle, hors CI par défaut
(cible `make eval-ai`).

## Décisions

Prises le 1er novembre 2026 :

- Par défaut, l'IA est désactivée : un projet non réglé n'appelle aucun modèle.
- Envoi de code à un fournisseur externe : autorisé projet par projet, par un
  administrateur d'organisation, avec un événement d'audit ; la configuration de l'instance
  peut interdire tout fournisseur externe.
- Modèle Anthropic par défaut : `claude-sonnet-5-5`, à confirmer (ou changer) au vu du
  rapport d'évaluation sur le corpus.
- Seuils sur le corpus annoté, pour les composants d'origine IA acceptés : taux de faux
  positifs inférieur ou égal à 5 %, rappel supérieur ou égal à 80 %. Ils valent aussi pour
  la recette (T18).

## Journal

Réalisé le 1er novembre 2026, branche `lot/T12-enrichissement-ia`, en autonomie (lot 2
enchaîné sans attendre l'utilisateur), en parallèle de T13, T14 et T17 : les décisions
marquées **[à relire]** n'ont pas été validées explicitement.

### Livré

- `internal/llm` : interface `Provider` (`Model`, `External`, `Complete`), messages et
  outils, boucle `Run` (budget de tours et de jetons d'entrée et de sortie, outil inconnu
  refusé, relance unique sans soumission, erreurs `ErrBudget`, `ErrNoResult`,
  `ErrRefused`, `ErrTruncated`) ; fournisseur **Anthropic** par le SDK Go officiel
  (`anthropic-sdk-go/v2` v2.4.0) construit sans environnement, prompt système et outils
  marqués pour le cache de prompt, blocs de raisonnement renvoyés tels quels ;
  fournisseur **Ollama** (`/api/chat`, bibliothèque standard) ; `llmtest` : faux
  fournisseur scénarisé (`Script`) et enregistreur (`Recorder.Sent`).
- `internal/repoagent` :
  - configuration `ai.*` (`LOTOR_REPO_AI_*`) : modèle local, fournisseur externe et sa clé
    (`credential:anthropic-api-key`), budgets, durée, `full_interval`, exclusions ;
  - outils `list_dir`, `read_file`, `search`, `submit_candidates` sur un `os.Root`
    (`ai_workspace.go`, `ai_tools.go`) : bornes, résultats en JSON, fichiers exclus
    (motifs `DefaultExclude` + `ai.exclude`, clés privées détectées dans le contenu)
    invisibles et indiscernables d'un fichier absent, budget d'octets lus, soumission
    validée par schéma JSON ;
  - vérificateur déterministe (`ai_verify.go`), motifs de rejet comptés et journalisés ;
  - fusion dans le SBOM Syft (`ai_merge.go`) : `lotor:origin=ia`, `lotor:confidence`,
    `lotor:model`, `evidence` CycloneDX 1.6, empreinte du fichier d'une bibliothèque
    JavaScript ou CSS recopiée, Syft l'emporte ; statut `lotor:enrichment`
    (`complete`, `incomplete`, `carried`), `lotor:enrichment-model`,
    `lotor:enrichment-prompt` ;
  - analyse incrémentale (`ai_agent.go`) : état par référence, composants IA de
    l'instantané courant lus au serveur après un redémarrage, fichiers modifiés par la
    comparaison de la forge, analyse complète à `full_interval`, commits intermédiaires
    d'un rattrapage sans appel au modèle ;
  - prompt système versionné et embarqué (`prompts/system-v1.md`, `PromptVersion`).
- `internal/agentclient` : `AIComponents` ; API : `AgentProject.ai_mode` (réglage
  effectif) et `GET /api/v1/agent/refs/{id}/ai-components` (`listAIComponents`).
- Serveur : migration **018** (renumérotée après la fusion de T17) (`projects.ai_mode`, `snapshots.enrichment`,
  `snapshots.enrichment_model`) ; `project.SetAIMode` (audit `project.ai_mode_changed`),
  `project.RefOfAgent`, `AIMode.Effective` ; permission d'organisation `ai.external`
  (matrice, `permissions.md` régénéré) ; fragment `AI` (`ai.forbid_external`) ; statut
  d'enrichissement lu dans les métadonnées CycloneDX (`sbom.Document.Enrichment`) et
  rangé avec l'instantané ; `inventory.AIComponents`, `sbom.FirstOccurrence`.
- Écrans : paramètres du dépôt (section **Enrichissement IA**), fiche composant (bloc
  **preuve** par occurrence IA de la version, colonne **Emplacement**, maquette « 7 ·
  Fiche composant (origine IA) »), fiche projet (réglage IA, **Inventaire courant** par
  origine et statut), instantanés (statut et modèle, avertissement « enrichissement
  incomplet ») ; `web/static/css/components/proof.css` porté du design de référence ;
  traductions FR et EN.
- Corpus annoté `testdata/ai-corpus/` (9 cas : JS minifié, Dockerfile, CDN,
  `curl | sh`, C recopié, deux pièges, deux dépôts hostiles avec témoins) et son README ;
  cible `make eval-ai` (`ai_eval_test.go`, étiquette `evalai`, rapport JSON, seuils).
- `cmd/lotor-repo-agent` câble les modèles ; `deploy/lotor-repo-agent/` : section `ai`
  de `config.example.yaml`, credential `anthropic-api-key` (commenté) dans l'unité ;
  `config.example.yaml` du serveur (`ai.forbid_external`).
- Docs : ADR 0042 à 0044 ; `architecture.md` (§ 3, 5, 6, 8, 10, 11, 17) ;
  `docs/operations.md` (« Enrichissement IA » : réglages, politique d'envoi de code,
  Ollama, Anthropic, budget, preuve ; « Évaluer l'enrichissement IA ») ;
  `docs/utilisation.md` (« Composants trouvés par l'IA ») ; modèle de menace (cinq
  menaces) ; `CHANGELOG.md` ; `doc.go` de `llm` et `repoagent`.

### Tests

- `internal/llm` : boucle (fin sur l'outil final, budget de tours, de jetons d'entrée et
  de sortie, résultat accepté au dernier tour, relance unique, refus, troncature, outil
  inconnu, erreur d'outil) ; Anthropic contre `httptest` (forme de la requête, aucune
  variable `ANTHROPIC_*` prise en compte, blocs de raisonnement renvoyés, raisons d'arrêt,
  erreur résumée sans corps) ; Ollama (messages, options, appels d'outils, erreurs).
- `internal/repoagent` : **vérificateur en table** (une quarantaine de cas, dont version inventée,
  version préfixe d'une autre, extrait absent ou trop loin, chemins hors arborescence,
  fichier exclu, clé privée, binaire, documentation, manifeste, fichier qui s'adresse au
  modèle, extrait qui cite un purl, purl invalide ou incohérent, versions mouvantes) ;
  exclusions, chemins, outils (fichier exclu indiscernable d'un absent, recherche bornée,
  budget de lecture qui arrête l'analyse, lignes longues), schéma de soumission ;
  **corpus** : chaque annotation est prouvable (`TestCorpusAnnotationsAreProvable`),
  modèle crédule (`TestCorpusNaiveModel`), **dépôts hostiles**
  (`TestHostileRepositories` : faux fournisseur obéissant, enregistré ; aucun témoin hors
  arborescence, d'un fichier exclu, de l'environnement, aucune clé privée ni chemin du
  répertoire de travail envoyés ; seuls les composants annotés acceptés),
  `TestInventedCandidateRejected`, repli incomplet (erreur, sans soumission, tours et
  jetons épuisés), choix du modèle ; agent : **projet « IA désactivée » sans appel**
  (`TestDisabledProjectNeverCallsModel`, y compris « local » sans modèle local),
  composants prouvés relus par le décodeur du serveur, Syft l'emporte, SBOM Syft seul en
  cas d'échec, **analyse incrémentale** (lecture au serveur, fichiers modifiés, report,
  `full_interval`, repli en analyse complète), configuration.
- Intégration : `project` (réglage, audit, interdiction, serveur, archive, autre
  organisation ; `RefOfAgent`), `inventory` (composants IA et statut repris à chaque
  envoi), `web` : **bout en bout** `TestRepoAgentAIEnrichmentAgainstServer` (agent réel,
  git, Syft, faux fournisseur enregistré, serveur réel : composant IA rangé avec sa
  preuve, statut, route `ai-components` réservée à l'agent du projet, fiche composant et
  fiche projet accessibles, ni `.env` ni jeton envoyés) ; `TestProjectAISettings`
  (administrateur d'équipe : local oui, externe 403 ; administrateur d'organisation :
  externe ; instance qui l'interdit : 422 et réglage effectif `local` transmis ; journal) ;
  les tests de référence de T16 (droits par route, isolement) couvrent la nouvelle route.
  Vérifié en cassant la garde « fournisseur externe » : le test échoue (303 au lieu de
  403).

### Décisions

Décisions de la fiche appliquées (IA désactivée par défaut, fournisseur externe autorisé
par projet par un administrateur d'organisation et audité, interdiction possible par
l'instance, `claude-sonnet-5-5`, seuils 5 % et 80 %). Décisions prises pendant le lot,
toutes **[à relire]** :

- **SDK Go officiel d'Anthropic validé** (v2.4.0), construit par
  `option.WithoutEnvironmentDefaults()` ; client HTTP maison écarté ; pas de repli de
  modèle côté serveur sur refus ; Ollama en bibliothèque standard
  ([ADR 0042](../../docs/adr/0042-fournisseurs-de-modeles.md)).
- **Réglage par projet** `disabled`/`local`/`external`, permission d'organisation
  `ai.external`, `ai.forbid_external` qui ramène `external` à `local` sans réécrire les
  projets, choix du modèle par l'agent (externe, à défaut local)
  ([ADR 0043](../../docs/adr/0043-enrichissement-ia-prouve.md)).
- **Règles du vérificateur** au-delà de la fiche : preuve refusée dans la documentation,
  dans un manifeste que Syft lit, dans un fichier qui s'adresse à un modèle (marqueurs
  d'injection), extrait qui cite un purl ; tolérance de trois lignes ; nom cherché dans
  l'extrait et les trois lignes voisines ; cohérence type/fichier limitée aux images de
  conteneur et aux fichiers JavaScript/CSS (ADR 0043).
- **Statut `carried`** et commits intermédiaires d'un rattrapage sans appel au modèle ;
  statut dans les métadonnées CycloneDX plutôt que dans le contexte d'envoi (ADR 0043).
- **Confinement par la surface d'outils et `os.Root`, sans processus fils** : sous
  `DynamicUser`, un fils du même uid ne serait pas isolé des credentials ni de la mémoire
  du parent ([ADR 0044](../../docs/adr/0044-confinement-de-l-analyse-ia.md)).
- **Liste d'exclusion intégrée** (`DefaultExclude`) et détection des clés privées par le
  contenu ; fichiers exclus indiscernables d'un absent ; fichiers de plus de 2 Mio ni lus
  ni fouillés.
- **Budgets par défaut** : 40 tours, 600 000 jetons d'entrée, 40 000 de sortie, 8 192 par
  réponse, 1 Mio lu, 20 min ; analyse complète tous les 7 jours ; 200 fichiers modifiés
  au plus avant de basculer en analyse complète.
- **Empreinte du fichier** ajoutée à un composant IA JavaScript ou CSS recopié (recherche
  par empreinte, comme sur la maquette).
- **Prompt système en anglais** (langue de travail du modèle), versionné `v1`.
- Écarts à la maquette : pas de boutons « Confirmer la détection » / « Signaler une
  erreur » (revue humaine des détections : triage, T14 ou T18), pas de lien « Ouvrir dans
  le dépôt » (l'URL de forge n'est pas lue avec l'usage), extrait réduit à la ligne de la
  preuve (le serveur n'a pas les lignes voisines).

### Écarts

- **Mesure avec un vrai modèle non faite** : aucune clé d'API n'était disponible. Le
  critère « faux positifs ≤ 5 %, rappel ≥ 80 % » n'est donc **pas vérifié** ; le coût
  moyen par analyse n'est pas connu. Livrés : corpus annoté, faux fournisseur, harnais et
  rapport (`make eval-ai`, procédure dans `docs/operations.md`). À faire par
  l'utilisateur avec une clé ; T18 reprend la mesure pour la recette. Le modèle par défaut
  `claude-sonnet-5-5` reste « à confirmer » au vu de ce rapport.
- Ce que mesurent les tests déterministes (pas la qualité d'un modèle) : avec un modèle
  « crédule » qui soumet les composants attendus, chaque piège avec sa meilleure preuve
  et des versions inventées, le vérificateur retient les 10 composants attendus, rejette
  toutes les versions inventées, les composants demandés par les instructions
  malveillantes et les dépendances de manifeste, et laisse passer 4 pièges à preuve
  réelle (lodash et moment cités en commentaire, module `request` homonyme, version du
  dépôt) : 28,6 % de faux positifs **pour ce modèle fictif**. Seul un modèle qui suit le
  prompt écarte ces pièges ; c'est ce que `make eval-ai` mesure.
- Captures d'écran clair et sombre non faites ; la feuille `proof.css` reprend celle du
  design de référence et ses jetons `light-dark()` ; accessibilité vérifiée par `webtest`
  sur la fiche composant, la fiche projet et les paramètres ; audit RGAA du lot 2 en T18.
- Analyse limitée à la tête d'un rattrapage ; une référence très active voit ses commits
  intermédiaires « reportés », sans découverte nouvelle avant la tête.

### ADR créés

- [0042 — Fournisseurs de modèles](../../docs/adr/0042-fournisseurs-de-modeles.md).
- [0043 — Enrichissement IA prouvé](../../docs/adr/0043-enrichissement-ia-prouve.md).
- [0044 — Confinement de l'analyse IA](../../docs/adr/0044-confinement-de-l-analyse-ia.md).

### Mesures

- Rapport d'évaluation (précision, rappel, taux de faux positifs, coût moyen par
  analyse) : **non disponible**, voir Écarts.
- Couverture (unitaires et intégration) : `repoagent` 90,9 %, `llm` 90,5 %.
- Nouvelle dépendance : `go.mod` gagne six lignes (le SDK, `tidwall/gjson`, `sjson`,
  `match`, `pretty`, `standard-webhooks`).
