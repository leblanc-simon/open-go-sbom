// Package vuln gère la base de vulnérabilités commune aux instances et le catalogue
// global (§ 12 de l'architecture, ADR 0017).
//
//   - Checker obtient les nouvelles bases : job vulndb.check (liste de distribution,
//     téléchargement par un Fetcher injecté, SHA-256, installation complète) ou import
//     d'une archive ; l'archive validée est stockée par blocs (vulndb_archives) et devient
//     la cible (vulndb_state), avec la mise en file d'analysis.rescan_all.
//   - Manager tient la copie locale d'une instance worker : synchronisation sur la cible
//     depuis PostgreSQL, bascule atomique, une seule base ouverte derrière un verrou
//     lecture/écriture ; Ensure avant chaque analyse, Ready pour /readyz.
//   - UpsertCatalog et GetVulnerability tiennent le catalogue vulnerabilities.
//
// Le format de la base n'est connu que de l'adaptateur vuln/grype (Engine, Source) ;
// vuln/vulntest en fournit des faux pour les tests.
package vuln
