# 0043 — Enrichissement IA prouvé : réglage par projet, politique d'envoi de code, vérificateur, statut

- Statut : Accepté (décisions de la fiche T12 du 1er novembre 2026 ; leur mise en œuvre,
  prise en autonomie, est **à relire**)
- Date : 2026-11-01
- Lot : T12

## Contexte

La fiche T12 et les décisions du 1er novembre 2026 fixent : IA désactivée par défaut ;
envoi de code à un fournisseur externe autorisé projet par projet par un administrateur
d'organisation, audité, et interdit par l'instance si elle le veut ; modèle Anthropic par
défaut `claude-sonnet-5-5` ; aucun composant accepté sans preuve vérifiée de façon
déterministe ; repli sur le SBOM Syft seul, marqué « enrichissement incomplet », en cas
de budget dépassé ou d'erreur ; seuils sur le corpus annoté (faux positifs ≤ 5 %,
rappel ≥ 80 %). Restaient à fixer : la forme du réglage, le chemin de la décision
jusqu'à l'agent, les règles exactes du vérificateur, la transmission du statut et
l'analyse incrémentale.

## Décision

**Réglage et politique**

1. `projects.ai_mode` (migration 018) : `disabled` (défaut, aussi pour l'existant),
   `local` (modèle local seulement), `external` (fournisseur externe permis, à défaut le
   modèle local). Réglable pour un dépôt actif dans ses paramètres
   (`POST /o/{org}/projects/{slug}/ai`, droit `project.manage`).
2. Choisir `external` exige en plus la permission d'organisation `ai.external`
   (administrateur d'organisation, matrice des droits) : 403 sinon. Un administrateur
   d'équipe peut toujours revenir à `local` ou `disabled`. Chaque changement est
   journalisé (`project.ai_mode_changed`, ancien et nouveau réglage).
3. `ai.forbid_external` (configuration du serveur, faux par défaut) interdit tout
   fournisseur externe : le choix n'est plus proposé (422 s'il est posté), et le serveur
   transmet aux agents le **réglage effectif**, `external` ramené à `local`
   (`AgentProject.ai_mode`). Le réglage stocké ne change pas : lever l'interdiction rend
   aux projets leur autorisation.
4. L'agent choisit son modèle : `disabled` (ou valeur inconnue) → aucun ; `local` → le
   modèle local s'il est configuré, sinon aucun ; `external` → le fournisseur externe
   s'il est configuré, sinon le modèle local. Sans modèle, l'agent envoie le SBOM Syft
   sans propriété d'enrichissement, exactement comme en T08.

**Ce qui part vers le fournisseur**

5. Le prompt système versionné et embarqué (`prompts/system-v1.md`, `PromptVersion`),
   un message de tâche (slug du projet, commit, liste des fichiers modifiés et
   composants IA précédents), les descriptions et schémas des outils, et les résultats
   des outils : rien d'autre. Les outils (`list_dir`, `read_file`, `search`) sont en
   lecture seule, confinés par `os.Root` à l'arborescence de l'analyse (ADR 0044),
   bornés (500 entrées, 400 lignes et 32 Kio par lecture, lignes coupées à 2 000
   caractères, 50 résultats de recherche, expressions RE2), et décomptés d'un budget
   d'octets (`ai.max_read_kib`). Leurs résultats sont des objets JSON (donnée, jamais
   texte libre). `search` prend une expression RE2, sans retour arrière exponentiel.
6. **Fichiers exclus** : motifs intégrés (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.ssh`,
   `.aws`, `.npmrc`, `*.tfstate`, `credentials*`…, liste `DefaultExclude`) plus
   `ai.exclude`, appliqués à chaque élément du chemin, et tout fichier dont le contenu
   porte une clé privée (`-----BEGIN … PRIVATE KEY-----`, clé PuTTY). Un fichier exclu
   n'est ni listé, ni lu, ni fouillé, et répond comme un fichier absent ; `.git` est
   toujours exclu. Les fichiers binaires ou de plus de 2 Mio ne sont ni lus ni fouillés.
7. La seule sortie acceptée est l'appel `submit_candidates`, validé par son schéma JSON
   (`santhosh-tekuri/jsonschema`, déjà au § 5) puis décodé sans champ inconnu ; une
   soumission invalide est refusée au modèle (une nouvelle tentative possible), une
   seconde soumission ignorée.

**Vérificateur, seul juge**

8. Pour chaque candidat, dans l'arborescence au commit analysé : version concrète (ni
   plage, ni joker, ni `latest`, au moins un chiffre) ; fichier relatif dans
   l'arborescence, non exclu, texte ; **ni documentation** (`*.md`, `*.rst`, README,
   CHANGELOG, LICENSE…), **ni manifeste ou fichier de verrouillage que Syft lit**
   (`package.json`, `go.mod`, `requirements*.txt`…), **ni fichier qui s'adresse à un
   modèle ou à un outil d'analyse** (« ignore previous instructions », « note for AI
   models », noms des outils…) ; extrait retrouvé à la ligne annoncée à trois lignes près
   (espaces normalisés, un extrait peut couvrir des lignes consécutives) ; extrait qui
   ne cite pas un purl ; version présente dans l'extrait comme élément entier (`3.4`
   n'est pas dans `3.4.1`, un `v` en tête toléré) ; nom présent comme mot entier dans
   l'extrait ou les trois lignes voisines (casse, `-`, `_`, `.` indifférents ; dernière
   partie d'un nom à espace de noms acceptée) ; purl valide, canonique, d'un type connu,
   au même nom et à la même version ; type cohérent avec le fichier (`docker`/`oci` dans
   un Dockerfile, un Compose, un manifeste YAML… ; JavaScript ou CSS recopié en `npm`,
   `github` ou `generic`) ; pas de doublon. Tout échec rejette le candidat et compte son
   motif, journalisé ; un candidat n'est jamais corrigé.
9. Le vérificateur garantit qu'une preuve existe, pas que le composant est juste (une
   version citée dans un commentaire passe) : la qualité se mesure sur le corpus annoté
   (`testdata/ai-corpus`, `make eval-ai`).

**SBOM, statut, serveur**

10. Composants acceptés ajoutés au SBOM Syft avec `lotor:origin=ia`, `lotor:confidence`
    (confiance du modèle, quatre décimales), `lotor:model`, `evidence` CycloneDX 1.6
    (occurrence : fichier, ligne, extrait ; identité : purl, technique
    `source-code-analysis`), et l'empreinte SHA-256 du fichier pour une bibliothèque
    JavaScript ou CSS recopiée (recherche par empreinte). Dédoublonnage par `purl_base`
    et version : un composant déjà trouvé par Syft l'emporte toujours.
11. Statut dans les métadonnées : `lotor:enrichment` = `complete`, `incomplete` (budget
    de tours, de jetons d'entrée ou de sortie, d'octets lus, de durée dépassé ; erreur ou
    refus du fournisseur ; aucune soumission : SBOM Syft seul) ou `carried` (commit
    intermédiaire d'un rattrapage : aucun appel au modèle, composants IA précédents
    revérifiés et reportés), avec `lotor:enrichment-model` et
    `lotor:enrichment-prompt`. Le serveur range le statut et le modèle dans
    `snapshots.enrichment` et `snapshots.enrichment_model`, repris à chaque envoi d'un
    même commit, et l'affiche (fiche projet, liste et fiche des instantanés, avertissement
    pour un enrichissement incomplet).
12. Fiche composant : bloc « preuve » par occurrence d'origine IA de la version de la
    fiche (fichier, ligne, extrait, confiance écrite et graduée, modèle, version de
    l'agent, instantané, purl), colonne « Emplacement ». Fiche projet : composants de
    l'instantané courant de chaque référence par origine. Les filtres par origine
    existaient déjà (instantané, recherche).

**Analyse incrémentale**

13. L'agent garde en mémoire, par référence, le dernier commit analysé par le modèle, ses
    composants IA et la date de la dernière analyse complète. Au premier passage (ou
    après un redémarrage) il lit les composants IA de l'instantané courant
    (`GET /api/v1/agent/refs/{id}/ai-components`, 404 pour une référence d'un projet qui
    ne lui est pas confié, 1 000 au plus) et fait une analyse complète. Ensuite, la tête
    d'un rattrapage reçoit les fichiers modifiés depuis le dernier commit analysé
    (comparaison de la forge ; liste de plus de 200 fichiers ou comparaison impossible :
    analyse complète) et les composants précédents, toujours revérifiés de façon
    déterministe et reportés s'ils restent prouvés. Analyse complète au moins tous les
    `ai.full_interval` (7 jours). Les commits intermédiaires d'un rattrapage n'appellent
    pas le modèle (statut `carried`).

**Budgets par défaut** : 40 tours, 600 000 jetons d'entrée, 40 000 de sortie, 8 192 par
réponse, 1 Mio lu, 20 minutes par analyse.

## Conséquences

- « IA désactivée » est garanti par construction : aucun modèle n'est choisi, testé pour
  `disabled`, une valeur vide ou inconnue, et pour `local` sans modèle local.
- Les règles du vérificateur sur la documentation, les manifestes et les fichiers qui
  s'adressent au modèle écartent des preuves qui existent : un composant réellement
  livré mais cité seulement dans un README n'est plus trouvable par l'IA (prix accepté
  pour fermer la voie la plus simple d'injection). La liste des marqueurs d'injection est
  volontairement étroite ; un faux négatif reste soumis aux autres contrôles.
- La mesure de la précision, du rappel et du coût avec un vrai modèle reste à faire par
  l'exploitant (clé d'API) : les tests de la CI n'utilisent qu'un faux fournisseur.
- Un changement du prompt système crée un nouveau fichier et une nouvelle version, qui
  apparaît dans chaque SBOM (`lotor:enrichment-prompt`) : une baisse de qualité se relie
  à sa version.

## Alternatives écartées

- **Réglage d'organisation unique** : la décision veut un choix projet par projet.
- **Interdiction de l'instance appliquée en réécrivant les projets** : perdrait les
  autorisations données ; le réglage effectif calculé à la volée les garde.
- **Choix d'outil forcé pour la soumission** : refusé par le modèle par défaut ; la
  relance unique et la validation par schéma suffisent.
- **Vérificateur tolérant (correction de la ligne, du purl, de la version)** : un
  candidat corrigé n'est plus celui que le modèle a prouvé ; le rejet compte le motif et
  la qualité se mesure.
- **Appel au modèle pour chaque commit d'un rattrapage** : coût multiplié par
  `catchup.max_commits` pour des instantanés intermédiaires ; le report revérifié garde
  leurs composants prouvés.
- **Statut de l'enrichissement dans le contexte de l'envoi** : le SBOM porte sa propre
  provenance (métadonnées CycloneDX), lisible aussi hors de lotor.
