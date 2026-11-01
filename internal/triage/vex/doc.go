// Package vex écrit et lit les déclarations de triage (triage.Statement) aux formats
// OpenVEX 0.2.0 et CycloneDX 1.6 (VEX dans un BOM), en JSON (ADR 0036).
//
// Correspondance des statuts :
//
//	lotor            OpenVEX                                    CycloneDX (analysis.state)
//	in_triage        under_investigation                        in_triage
//	affected         affected (commentaire en action_statement) exploitable
//	not_affected     not_affected + justification               not_affected + justification
//	false_positive   not_affected, component_not_present,       false_positive
//	                 marque [lotor:status=false_positive]
//	risk_accepted    affected, marque                           exploitable, response will_not_fix,
//	                 [lotor:status=risk_accepted;expires=…]     propriétés lotor:triage_status et
//	                                                            lotor:triage_expires
//	fixed            fixed                                      resolved (resolved_with_pedigree à l'import)
//
// La justification est conservée telle qu'elle a été donnée ; un export vers l'autre
// format la traduit par la table de triage (Justification.In) et note la justification
// d'origine, sans quoi l'aller-retour la perdrait (même une correspondance réciproque
// change de liste) : marque
// [lotor:justification=…] dans status_notes d'OpenVEX (dont le schéma refuse toute
// propriété supplémentaire), propriété lotor:triage_justification en CycloneDX. La
// lecture reprend ces marques : un aller-retour dans le même format, ou d'un format à
// l'autre et retour, redonne statut, justification, commentaire et échéance.
//
// OpenVEX : une déclaration vise des produits identifiés par un purl (@id ou
// identifiers.purl) ; si un produit a des sous-composants, ce sont eux qui sont visés.
// CycloneDX : affects[].ref désigne un composant du BOM par son bom-ref, ou un purl.
// Decode borne la taille (MaxDocument) et le nombre de déclarations ; une déclaration
// au statut, à la justification ou à l'état inconnus, ou sans purl, est écartée et
// comptée (Document.Skipped). Les documents produits sont valides contre les schémas
// officiels (OpenVEXValidator, et le schéma CycloneDX 1.6 de sbom/schema).
package vex
