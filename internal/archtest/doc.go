// Package archtest vérifie les règles de dépendance entre paquets du § 4 de
// specs/architecture.md, à partir des imports directs que rapporte go list.
//
// Deux règles du § 4 ne se lisent pas dans les imports et restent du ressort de la
// relecture : « cmd ne contient aucune logique » et « pas de variable globale mutable ».
package archtest
