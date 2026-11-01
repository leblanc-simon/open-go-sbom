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
//     mis en file dans la même transaction (handler dans finding).
//
// Les écritures se font dans la transaction InOrg de l'appelant (Store), clés triées pour
// éviter les interblocages entre ingestions concurrentes ; la référence est verrouillée le
// temps de l'écriture, si bien que deux ingestions d'une même référence se succèdent. Un
// ensemble existant est verrouillé (FOR KEY SHARE) avant d'être réutilisé, pour que la
// rétention ne le supprime pas sous l'ingestion.
//
// # Différences (ADR 0038)
//
// Un instantané créé ou remplacé met en file inventory.diff : History.ComputeMissing
// enregistre (set_diffs, set_diff_items) la différence de chaque couple d'instantanés
// consécutifs d'une référence qui ne l'a pas encore. Deux versions d'un même purl_base
// forment une montée ou une descente, comparées par version.Comparer ; une même version
// aux qualificatifs changés reste un retrait et un ajout. La lecture d'un instantané donne
// son précédent et le décompte enregistré (frise) ; History.Diff compare deux instantanés
// quelconques d'un projet, depuis le stockage ou calculé à la demande. L'effet sur la
// sécurité vit dans finding (SnapshotEffect).
//
// # Rétention (ADR 0039)
//
// History.Retain applique RetentionPolicy à une organisation : tout instantané de la
// fenêtre (Days) est gardé, ainsi que les Count plus récents, le dernier de chaque mois
// au-delà (Monthly), le dernier d'une référence, celui en vigueur au début de la fenêtre
// et celui de la dernière analyse ; puis les réceptions terminées hors fenêtre, les
// ensembles et SBOM orphelins et les différences périmées sont supprimés. L'horizon
// enregistré (ReadRetention) dit en deçà de quelle date l'historique est réduit : la
// recherche à une date passée (T21) s'en sert pour avertir que ses résultats sont
// partiels.
package inventory
