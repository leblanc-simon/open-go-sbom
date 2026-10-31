// Package dashboard calcule les agrégats du tableau de bord d'organisation et de
// l'en-tête de la fiche projet, et tient les statistiques quotidiennes (ADR 0027).
//
// # Indicateurs
//
// Les indicateurs « instantanés » se lisent sur les tables courantes, dans une seule
// transaction en lecture seule (REPEATABLE READ : tous les chiffres d'une page viennent du
// même état) :
//
//   - constats ouverts par sévérité et KEV : constats open des références actives
//     (removed_at nul) des projets actifs (archived_at nul) ; à l'échelle d'un projet, ses
//     références actives, même s'il est archivé ;
//   - délai médian de correction par sévérité : resolved_at − first_seen_at des constats
//     résolus pendant la période, des projets actifs ;
//   - projets les plus exposés (risque maximal ouvert), composants vulnérables les plus
//     répandus (familles purl_base, par nombre de projets touchés), agents muets (règle
//     agent.Agent.StateAt, celle des écrans des agents).
//
// Seules les séries temporelles lisent org_daily_stats et project_daily_stats ; le
// dernier point d'une série est l'état courant, si bien que le premier jour la courbe n'a
// qu'un point, jamais une série inventée.
//
// # Statistiques quotidiennes
//
// L'échéance StatsAllKind (toutes les heures) met en file un StatsOrgKind par
// organisation active, liste obtenue par crossorg.ListOrganizations (aucune nouvelle
// fonction inter-organisations). StatsOrgKind enregistre l'état observé sous la date UTC
// du jour : une ligne par jour, réécrite à chaque passage, donc l'état de fin de journée
// une fois le jour écoulé. Les deux handlers sont idempotents.
package dashboard
