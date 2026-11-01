# 0044 — Confinement de l'analyse IA : os.Root et surface d'outils, sans processus fils

- Statut : Accepté (décision prise en autonomie le 1er novembre 2026, **à relire**)
- Date : 2026-11-01
- Lot : T12

## Contexte

La fiche T12 demande un ADR : « séparation des privilèges (analyse et appels au modèle
dans un processus fils sans accès aux secrets des forges) ou confinement par `os.Root`
seul ». L'analyse IA lit le contenu d'un dépôt non fiable, l'envoie à un modèle dont les
réponses sont elles aussi non fiables (injection d'instructions), alors que le même
processus détient le jeton d'agent, les clés des forges et la clé d'API du modèle.

Ce qu'un attaquant contrôle : le contenu des fichiers du dépôt, donc ce que le modèle
lit, donc (par injection) les appels d'outils que le modèle demande et les candidats
qu'il soumet. Ce qu'il ne contrôle pas : le code de l'agent. Le modèle n'exécute rien ;
ses demandes passent par quatre gestionnaires écrits en Go.

Ce que permettrait un processus fils sous `DynamicUser` (unité systemd de T08) : il
tournerait sous le même utilisateur. Il pourrait donc relire les credentials systemd
(`$CREDENTIALS_DIRECTORY`, lisibles du service), `/proc/<pid du parent>/environ` et la
mémoire du parent (même uid ; `ProtectProc=invisible` ne masque que les processus des
autres utilisateurs). Une séparation réelle demanderait un autre uid ou un espace de noms
utilisateur, que l'unité durcie (`NoNewPrivileges`, aucune capacité,
`RestrictNamespaces=yes`) interdit justement, et un canal de communication à protéger à
son tour.

## Décision

1. **Pas de processus fils** : l'analyse IA tourne dans le processus de l'agent ; le
   confinement repose sur la surface d'outils et sur `os.Root`.
2. **Surface fermée** : le modèle n'a que `list_dir`, `read_file`, `search` (lecture
   seule) et `submit_candidates` ; un outil inconnu reçoit une erreur. Aucun outil
   n'écrit, n'exécute ni n'accède au réseau ; le seul appel réseau de l'analyse est celui
   du fournisseur, construit par l'agent.
3. **Tout accès aux fichiers par un `os.Root`** ouvert sur l'arborescence extraite de
   l'analyse en cours : chemins absolus et remontées refusés avant même l'`os.Root`
   (`clean`), qui refuse à son tour toute sortie et tout lien hors de la racine ; l'arbre
   ne contient d'ailleurs aucun lien symbolique (`core.symlinks=false` et parcours de
   contrôle, ADR 0023). Le vérificateur lit par le même `os.Root`.
4. **Secrets hors de portée par construction** : l'enrichisseur ne reçoit ni la
   configuration des forges, ni le jeton d'agent, ni les identifiants de clonage (passés
   à git par son environnement, jamais écrits dans l'arborescence) ; la clé d'API n'est
   connue que du client du fournisseur. Les fichiers sensibles du dépôt lui-même sont
   exclus (ADR 0043).
5. **Preuve par les tests** : sur les dépôts hostiles du corpus, un faux fournisseur qui
   obéit aux instructions malveillantes (lecture de `../`, de `/etc/passwd`, de
   `/proc/self/environ`, des fichiers exclus, recherche des clés privées et des témoins,
   soumission de composants inventés) est enregistré ; aucun témoin placé hors de
   l'arborescence, dans un fichier exclu ou dans l'environnement, aucune clé privée ni
   aucun chemin du répertoire de travail n'apparaît dans les échanges ; aucun composant
   non prouvé n'est accepté. Un test de bout en bout fait de même avec l'agent réel, le
   serveur réel et le jeton d'agent.
6. La séparation en processus sera réexaminée si l'analyse doit un jour exécuter du code
   du dépôt ou un analyseur natif (aujourd'hui exclu), ou si l'unité peut obtenir un uid
   distinct pour l'analyse ; la revue de sécurité du lot 2 (T18) relit cette décision.

## Conséquences

- La garantie repose sur le code des quatre gestionnaires et sur `os.Root` (bibliothèque
  standard, Go 1.24+) : toute évolution des outils est un changement de sécurité, relu
  comme tel et couvert par les tests des dépôts hostiles.
- Un défaut mémoire du runtime Go dans le traitement du JSON du modèle donnerait accès au
  processus entier ; ce risque est jugé faible (Go sûr en mémoire, entrées bornées) au
  regard d'une séparation qui, sous le même uid, ne protégerait pas les secrets.
- Pas de canal inter-processus ni de second binaire à déployer.

## Alternatives écartées

- **Processus fils sous le même uid** : n'isole pas des credentials systemd ni de la
  mémoire du parent ; complexité (sérialisation, supervision, arrêt) sans gain réel.
- **Processus fils sous un autre uid ou dans un espace de noms** : exige des privilèges
  que l'unité retire volontairement (`NoNewPrivileges`, `RestrictNamespaces`), ou un
  second service systemd avec son propre utilisateur et un canal local à authentifier ;
  disproportionné tant que l'analyse n'exécute rien.
- **Confinement par chemins nettoyés seulement (`filepath.Clean`)** : contournable par
  un lien symbolique ou une course ; `os.Root` résout chaque composant dans la racine.
