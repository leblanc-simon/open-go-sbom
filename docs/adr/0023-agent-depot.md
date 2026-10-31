# 0023 — Pipeline de l'agent dépôt et accès aux forges

- Statut : Accepté
- Date : 2026-10-31
- Lot : T08

## Contexte

`lotor-repo-agent` reçoit des webhooks venus d'Internet, détient les secrets des forges et
traite le contenu de dépôts non fiables. La fiche T08 fixe le cadre : GitHub App et GitLab
par compte de service, pas de file durable côté agent, rattrapage périodique, clonage par
le binaire `git` sous environnement maîtrisé, secrets hors du fichier de configuration.
Restaient à préciser : ce qu'un webhook déclenche, comment obtenir un commit précis (y
compris un commit ancien à rattraper), comment rendre un renvoi sans effet côté serveur,
ce que Syft a le droit de faire pendant le scan, et la forme des références aux secrets.

## Décision

1. **Un webhook n'est qu'un signal.** Après vérification de sa signature, il met en file
   la référence poussée ; le travailleur résout lui-même la tête de la référence auprès de
   la forge (`ResolveRef`) et la compare au dernier commit connu. Le commit annoncé par
   le webhook n'est jamais analysé tel quel : un webhook rejoué, ancien ou en retard ne
   peut pas faire d'un commit dépassé l'instantané courant (le serveur retient le plus
   récent par date de scan). Les livraisons déjà reçues (`X-GitHub-Delivery`,
   `X-Gitlab-Event-UUID`) sont en plus écartées par un ensemble borné en mémoire.
2. **Rattrapage** : au démarrage, à chaque `catchup.interval` et quand un webhook vise un
   dépôt inconnu du catalogue (au plus une fois par minute). Base de comparaison : le
   dernier commit envoyé par l'instance, sinon `TrackedRef.last_snapshot.commit` du
   serveur. Pour une branche, les commits de la comparaison de la forge (base exclue, tête
   incluse), du plus ancien au plus récent, bornés aux `catchup.max_commits` plus récents ;
   la tête seule pour une étiquette, une première analyse ou une comparaison impossible.
3. **File** en mémoire, bornée et dédoublonnée par référence ; une référence n'est jamais
   traitée par deux travailleurs à la fois (ses commits partent dans l'ordre), et une
   demande reçue pendant son traitement le relance à la fin. File pleine : la demande est
   perdue (503 au webhook), le rattrapage la refera.
4. **Extraction d'un commit précis** : `git init --template=`, puis `git fetch --depth 1
   --no-tags --no-recurse-submodules <url> <commit>`, `git checkout --detach <commit>`,
   vérification de `HEAD`, suppression de `.git`. La fiche citait `clone --depth 1
   --single-branch` : un clone de branche ne contient que sa tête, pas les commits à
   rattraper ; récupérer le commit par son identifiant donne le même transfert minimal
   (GitHub et GitLab acceptent un `want` sur un commit atteignable). Environnement de git
   entièrement construit (rien d'hérité de l'agent) : `GIT_CONFIG_NOSYSTEM`,
   `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_ALLOW_PROTOCOL` réduit au
   schéma de l'URL, `core.symlinks=false`, `core.hooksPath=/dev/null`, LFS inerte,
   `http.followRedirects=false`, `transfer.fsckObjects=true`, identifiants en en-tête
   `Authorization` par `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`. git tourne dans son
   propre groupe de processus, tué en entier à l'annulation. La taille du répertoire est
   mesurée toutes les 200 ms pendant le clonage ; au-delà de `work.max_clone_mib`, git est
   tué. Après extraction, un parcours par `os.Root` refuse tout lien symbolique restant.
5. **Scan Syft hors ligne et sans exécution** : source `dir` bornée à l'arborescence
   (`WithBasePath`), catalogage des fichiers désactivé, et dans les catalogueurs :
   `golang.UsePackagesLib=false` (Syft l'active par défaut : il lance `go list` via
   `golang.org/x/tools/go/packages`, donc la chaîne Go sur le dépôt, avec téléchargements
   possibles), aucune recherche de licence distante ni dans les caches de l'agent, Java
   sans réseau ni dépôt Maven local. Le pilote SQLite exigé par Syft est importé par
   `repoagent` lui-même.
6. **SBOM déterministe** : CycloneDX 1.6 de `cyclonedxhelpers`, sans `serialNumber` ni
   `metadata.timestamp` (facultatifs), composant décrit = slug du projet et commit (à la
   place du chemin temporaire), `lotor:origin=syft` sur chaque composant. Deux analyses
   du même commit donnent les mêmes octets : le serveur répond 200 sans rien créer.
7. **Échecs** : un dépôt trop gros, un lien symbolique restant ou un refus définitif du
   serveur (4xx hors 429) marquent le commit en échec dans un ensemble borné en mémoire,
   non retenté avant redémarrage ; un délai dépassé ou une erreur réseau sont retentés au
   passage suivant. Un commit en échec n'empêche pas l'analyse des suivants.
8. **Secrets** désignés par `credential:<nom>` (lu dans `$CREDENTIALS_DIRECTORY`) ou par un
   chemin absolu de fichier ordinaire sans aucun droit pour le groupe ni les autres ; tout
   autre fichier est refusé au démarrage. Aucun champ de la configuration ne reçoit une
   valeur secrète.
9. **GitHub App** : JWT RS256 de 9 minutes antidaté d'une minute ; installation cherchée
   par dépôt (ou fixée) et mise en cache ; jeton d'installation demandé avec
   `permissions: {contents: read}` quels que soient les droits de l'application, mis en
   cache par installation jusqu'à cinq minutes de son expiration. **GitLab** : jeton
   d'accès (`read_api`, `read_repository`), `X-Gitlab-Token` comparé en temps constant
   sur les SHA-256 des deux valeurs.

## Conséquences

- Un webhook coûte une résolution de référence ; un passage de rattrapage, un appel par
  référence suivie (plus une comparaison s'il y a du neuf).
- Une référence très active voit au plus `catchup.max_commits` commits par passage ; les
  plus anciens sont sautés, ce qui est journalisé implicitement par l'écart.
- L'état en mémoire (dernier envoi, échecs, livraisons vues) disparaît au redémarrage :
  sans conséquence, la base de comparaison redevient celle du serveur.
- Un commit en échec définitif est retenté à chaque redémarrage.
- Le graphe de modules gagne les fournisseurs de sources de Syft (stéréoscope, clients de
  registres) qu'importe `syft.GetSource`, tous indirects ; `modernc.org/sqlite` devient
  direct (déjà validé, § 5).

## Alternatives écartées

- **Analyser le commit annoncé par le webhook** : un webhook rejoué (GitHub ne signe pas
  d'horodatage) ferait d'un ancien commit l'instantané courant.
- **`git clone --single-branch --branch <réf>`** puis vérification : ne permet pas
  d'extraire un commit ancien à rattraper, et la tête peut avoir bougé entre la
  résolution et le clonage.
- **Bibliothèque git en Go (go-git)** : dépendance nouvelle, alors que le § 5 retient le
  binaire `git` ; les protections (liens, crochets, protocoles) y seraient à refaire.
- **Identifiants dans l'URL ou par `credential.helper`** : l'URL apparaît dans `ps` et
  dans les messages d'erreur de git ; un assistant d'identifiants est un programme de plus
  à exécuter.
- **Mesurer la taille par un quota de système de fichiers** : dépend de l'hôte ;
  la mesure périodique suffit à borner le disque à quelques centaines de millisecondes de
  transfert près.
- **Garder les composants avec numéro de série et horodatage** : chaque analyse d'un même
  commit créerait une nouvelle ingestion côté serveur.
