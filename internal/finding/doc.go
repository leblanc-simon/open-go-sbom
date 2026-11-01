// Package finding analyse les références et tient les constats (référence × composant ×
// vulnérabilité), § 12 de l'architecture, ADR 0018.
//
//   - Analyzer est le handler d'analysis.ref : correspondance du SBOM d'origine de
//     l'ensemble courant hors transaction, puis écriture sous verrou de ligne de la
//     référence après contrôle de l'ensemble et de la base cible ; idempotent (même
//     ensemble, même base : rien à faire). Il porte aussi analysis.rescan_all et
//     analysis.rescan_org (réanalyse du parc après un changement de cible).
//   - Cycle de vie : création, prolongation, résolution (composant retiré ou plus
//     signalé) et réouverture, historique dans finding_events.
//   - Service sert les lectures des écrans (onglet « Constats », fiches vulnérabilité et
//     composant) et l'effet sur la sécurité du passage d'un instantané à un autre
//     (SnapshotEffect, ADR 0038) : constats introduits et résolus, calculés à la lecture.
//   - Un constat garde l'instantané qui l'a vu en dernier tant que la rétention ne l'a pas
//     supprimé (snapshot_id mis à nul, ADR 0039).
package finding
