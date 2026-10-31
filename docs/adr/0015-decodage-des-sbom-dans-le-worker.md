# 0015 — Décodage des SBOM dans le processus worker, sous bornes préalables, plutôt qu'en sous-processus

- Statut : Accepté
- Date : 2026-10-31
- Lot : T05

## Contexte

Un SBOM vient d'un agent : son contenu n'est pas fiable (§ 19 de l'architecture). Le
décoder demande de le charger en mémoire, de le valider par un schéma JSON et de le passer
aux décodeurs de Syft (cyclonedx-go, tools-golang, décodeur Syft JSON), du code tiers
volumineux. Le § 11 demande d'étudier, pendant T05, une isolation du décodage en
sous-processus limité en temps et en mémoire, plutôt que dans le processus worker.

Mesures (T05, machine de développement, 4 cœurs, sans `-race`), du document en mémoire au
`sbom.Document` normalisé, bornes préalables et validation par schéma comprises :

| Document | Taille | Composants | Durée | Pic du tas |
| --- | --- | --- | --- | --- |
| Hôte Ubuntu, CycloneDX 1.7 (Syft) | 1,4 Mio | 837 | 0,25 s | + 32 Mio |
| Hôte Ubuntu, SPDX 2.3 (Syft) | 2,0 Mio | 837 | 0,36 s | + 31 Mio |
| Hôte Ubuntu, Syft JSON | 1,5 Mio | 837 | 0,21 s | + 20 Mio |
| Synthétique, CycloneDX 1.6 | 1,0 Mio | 5 000 | 0,41 s | + 38 Mio |
| Synthétique, CycloneDX 1.6 | 10,3 Mio | 50 000 | 4,7 s | + 326 Mio |

Le pic du tas vaut environ trente fois la taille du document ; le temps croît linéairement.
La lecture préalable en flux (`sbom.Precheck` : taille, profondeur, nombre de composants)
coûte 1 à 2 % du total et s'arrête à la première borne franchie, sans rien garder.

## Décision

Le décodage s'exécute **dans le processus worker**, dans le job `ingest.decode`, jamais dans
la requête HTTP, protégé par :

1. des **bornes préalables** vérifiées avant tout décodage complet : taille reçue
   (`ingest.max_upload_mib`, refus 413 dans la requête), taille décompressée
   (`ingest.max_decompressed_mib`, contrôlée en flux à la réception d'un envoi gzip puis de
   nouveau dans le job), profondeur JSON (`ingest.max_depth`) et nombre de composants
   (`ingest.max_components`), lues en flux par un analyseur borné, sans pile proportionnelle
   au document ; leurs valeurs par défaut (32 Mio, 64 Mio, 64, 50 000) bornent le pic d'un
   job à environ 2 Gio dans le pire cas, et à quelques centaines de Mio pour les SBOM réels ;
2. le **plafond de jobs simultanés par organisation** (`workers.org_limit`, défaut 2) et le
   nombre de workers de l'instance (`workers.concurrency`) ;
3. un **délai par job** (`ingest.decode_timeout`, défaut 5 min) ;
4. la **récupération des paniques** : l'adaptateur `sbom/syft` transforme une panique d'un
   décodeur en refus `error.ingest.decode_failed` (le runner de la file récupère aussi
   toute panique d'un handler) ;
5. une **validation par le schéma officiel** avant le décodeur tiers, qui refuse tôt les
   structures inattendues.

Le dimensionnement est documenté dans `docs/operations.md` (« Ingestion ») : une instance
worker prévoit, par job de décodage simultané, une trentaine de fois la taille du plus gros
SBOM attendu, et peut poser `GOMEMLIMIT`. Une instance purement web (`workers.enabled:
false`) ne décode jamais rien ; elle ne fait que recevoir et stocker.

L'isolation en sous-processus reste l'évolution prévue si la mesure en production montre
un besoin (OOM d'un worker, décodeur bloqué malgré le délai) ; elle ne demanderait que de
remplacer l'appel à `sbom/syft.Decode` dans `ingest`, l'entrée (blob) et la sortie
(`sbom.Document` sérialisable en JSON) étant déjà délimitées.

## Conséquences

- Un document pathologique dans les bornes peut occuper un worker jusqu'à son délai et
  quelques centaines de Mio à 2 Gio de mémoire ; il ne bloque pas les autres organisations
  (plafond par organisation) et ne laisse aucun instantané partiel (rangement dans une seule
  transaction après le décodage).
- Un OOM du processus tue aussi les autres jobs en cours de l'instance ; la file les
  reprend à l'expiration de leur bail (sémantique au moins une fois, handlers idempotents).
- Les bornes sont des réglages d'exploitation : les relever demande de relever la mémoire
  des workers en proportion.

## Alternatives écartées

- **Sous-processus du même binaire** (`lotor-server decode`, blob sur l'entrée standard,
  `sbom.Document` en JSON sur la sortie, `exec.CommandContext` pour le délai) : isole les
  paniques et les fuites, mais la limite de mémoire n'est fiable qu'avec un cgroup (Linux,
  droits de délégation systemd) — `RLIMIT_AS` interagit mal avec le ramasse-miettes et les
  réservations d'adresses de Go, et n'existe pas de la même façon ailleurs. Il ajoute un
  démarrage de processus (et la mémoire d'un second runtime Go) par SBOM, une
  sérialisation de plus, et un mode d'exécution supplémentaire à tester et à déployer
  (paquets, Containerfile, unités systemd). Sans mesure d'un besoin réel, ce coût n'est pas
  justifié.
- **Sous-processus limité par cgroup (systemd-run, conteneur)** : dépendance au système
  hôte et à des droits que l'instance n'a pas forcément ; hors du principe « un binaire, tout
  embarqué ».
- **Décodage dans la requête HTTP** : lierait la durée de la requête de l'agent à celle du
  décodage et ferait porter la charge aux instances web ; exclu par le § 11.
- **Décodeur en flux maison (sans charger le document)** : supprimerait le pic mémoire mais
  dupliquerait les décodeurs de Syft et perdrait la garantie que l'analyse (T06), qui passe
  par Syft, lit les mêmes paquets et les mêmes purl.
