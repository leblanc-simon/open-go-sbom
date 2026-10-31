// Package sbom définit le modèle interne d'un SBOM (Document, Component), la
// canonicalisation des purl, la normalisation des composants, l'empreinte d'inventaire et
// les bornes préalables lues en flux (Precheck). Il ne dépend d'aucune bibliothèque
// d'Anchore : le décodage des formats vit dans sbom/syft, la validation par schéma dans
// sbom/schema.
//
// Règles :
//
//   - un composant est identifié par son purl canonique (CanonicalPURL) : type, espace de
//     noms et nom selon les règles de chaque type, qualificatifs triés et encodés ;
//     aucun qualificatif d'identité (distro, arch, epoch, upstream…) n'est retiré ;
//   - un composant sans purl utilisable reçoit pkg:generic/<nom>@<version> et le drapeau
//     WeakID (« identification faible ») ;
//   - l'empreinte d'inventaire (Fingerprint) ne porte que sur les composants normalisés :
//     ni horodatage, ni numéro de série, ni outil, ni ordre des composants du document.
package sbom
