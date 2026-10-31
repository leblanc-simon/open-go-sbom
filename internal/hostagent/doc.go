// Package hostagent porte le pipeline de l'agent serveur (lotor-host-agent) : inventaire
// de l'hôte avec Syft et envoi conditionnel au serveur.
//
// Un cycle (Agent.Cycle) :
//
//  1. inscription au premier démarrage : le jeton d'inscription (fichier en 0600 ou
//     credential systemd « enrollment-token ») est échangé contre un jeton d'agent,
//     gardé dans le répertoire d'état (Store, 0700, fichiers en 0600) ;
//  2. lecture du projet d'hôte confié à l'agent (listAgentProjects) ;
//  3. scan de la racine (SyftScanner) : catalogueurs d'un système installé, sans
//     catalogage de fichiers, exclusions par défaut (DefaultExclusions : systèmes de
//     fichiers virtuels et stockages de conteneurs, qui relèvent de T13), montages réseau
//     et de conteneurs (lus dans /proc/self/mountinfo) et exclusions configurées ;
//  4. empreinte d'inventaire du SBOM produit, calculée par le même adaptateur et la même
//     fonction que le serveur (sbom/syft.Decode puis sbom.Fingerprint) ;
//  5. empreinte identique à celle du dernier envoi rangé : signal de vie avec compte rendu
//     d'inventaire (le serveur avance la date de dernière analyse, ou réclame le SBOM s'il
//     ne connaît pas cet inventaire) ; sinon envoi du SBOM (Syft JSON, gzip) puis attente
//     de son rangement. L'empreinte n'est retenue qu'une fois le SBOM rangé.
//
// Agent.Run (mode daemon) fait un cycle à l'échéance de scan.interval et envoie un signal
// de vie toutes les scan.poll_interval ; une demande de scan faite dans l'interface
// (scan_requested) déclenche un cycle aussitôt. Agent.RunOnce (mode oneshot) fait un seul
// cycle, pour un timer systemd.
//
// Rien d'autre ne sort de l'hôte que le SBOM et son contexte (os-release, noyau,
// architecture, nom d'hôte, durée du scan). Le paquet ne dépend d'aucun paquet serveur.
package hostagent
