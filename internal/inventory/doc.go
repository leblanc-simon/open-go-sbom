// Package inventory stocke les composants de chaque organisation, les ensembles
// d'inventaire adressés par contenu et les instantanés des références suivies (§ 8 et § 11
// de l'architecture).
//
// Règles :
//
//   - un composant est unique par (organisation, purl canonique) ; ses CPE et empreintes de
//     fichier s'accumulent, le reste ne change plus ;
//   - un ensemble d'inventaire est identifié par son empreinte (sbom.Fingerprint) : deux
//     instantanés au même inventaire partagent le même ensemble, écrit une seule fois ;
//   - dépôt : un instantané par (référence, commit), même si l'inventaire n'a pas changé ;
//     un nouvel envoi du même commit au même inventaire ne crée rien, à un autre
//     inventaire il remplace l'ensemble de l'instantané ;
//   - hôte : un envoi identique à l'inventaire courant n'avance que la date de dernière
//     analyse (last_scanned_at) ; sinon il crée un instantané ;
//   - l'instantané courant d'une référence (ref_current) est le plus récent par date de
//     scan, puis par création ; quand l'ensemble courant change, un job analysis.ref est
//     mis en file dans la même transaction (son handler arrive en T06).
//
// Les écritures se font dans la transaction InOrg de l'appelant (Store), clés triées pour
// éviter les interblocages entre ingestions concurrentes ; la référence est verrouillée le
// temps de l'écriture, si bien que deux ingestions d'une même référence se succèdent.
package inventory
