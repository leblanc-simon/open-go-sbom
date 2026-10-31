// Package ingest reçoit les SBOM des agents, stocke le brut compressé et dédoublonné, et
// pilote leur décodage par le job ingest.decode (§ 11 de l'architecture).
//
// Réception (Receive), dans la requête de l'agent : contexte validé, référence confiée à
// l'agent (project.RefForAgent), SBOM lu en flux sous deux bornes (taille reçue, taille
// décompressée d'un envoi gzip), empreinte SHA-256 du JSON, blob stocké compressé et
// dédoublonné, ingestion créée et job mis en file dans la même transaction. Aucun
// décodage dans la requête. Un envoi qu'on ne peut pas stocker (trop gros une fois
// décompressé, flux gzip corrompu) devient une ingestion « failed » avec sa clé d'erreur ;
// un envoi qui dépasse la taille reçue est refusé (413) sans ingestion. Un dépôt qui
// renvoie le même SBOM pour la même référence et le même commit retrouve l'ingestion
// existante, sans rien créer.
//
// Décodage (ingest.decode), dans un worker : bornes préalables lues en flux
// (sbom.Precheck), validation par le schéma officiel, décodage par sbom/syft,
// normalisation, puis rangement par inventory.Store et fin de l'ingestion dans une seule
// transaction. Un SBOM refusé termine l'ingestion en « failed » avec une clé traduisible,
// sans instantané partiel ; le job, lui, réussit (le réessayer ne changerait rien).
package ingest
