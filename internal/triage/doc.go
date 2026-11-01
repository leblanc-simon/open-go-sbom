// Package triage tient les décisions de triage des constats et leur statut effectif
// (T14, ADR 0035 à 0037).
//
// Modèle :
//
//   - Une décision (Decision, table triage_decisions) vise un couple (composant,
//     vulnérabilité) : pour un projet (ScopeProject), le composant exact — purl
//     canonique ; pour toute l'organisation (ScopeOrg), une famille de composants
//     (purl_base), éventuellement restreinte à une plage vers. Statuts (Status) : à
//     analyser, affecté, non affecté (justification VEX d'origine conservée telle quelle,
//     OpenVEX ou CycloneDX, ou à défaut une déclaration d'impact), faux positif, risque
//     accepté jusqu'à une date (ExpiresOn), corrigé.
//   - Le journal est en ajout seul (le rôle d'exécution n'a ni UPDATE ni DELETE sur la
//     table) : une décision, un retrait (ActionWithdraw) ou une échéance (ActionExpire)
//     ajoute une ligne, et la décision courante d'une clé est la plus récente (Current).
//   - Statut effectif (Resolver.Resolve) : décision courante du projet pour ce
//     composant, sinon la plus récente des décisions courantes de l'organisation dont la
//     plage contient la version, sinon « à analyser ».
//   - Les décisions s'appliquent aux constats après la correspondance (ADR 0035) : le
//     statut effectif est rangé sur chaque constat (findings.triage_status et
//     triage_decision_id), recalculé à chaque décision (Decide, Withdraw, Import, Expire)
//     pour tous les constats du couple (purl_base, vulnérabilité), et à la création d'un
//     constat par l'analyse (Classify, appelé par finding.Analyzer dans sa transaction) :
//     un constat apparu après une décision en hérite. Un verrou consultatif par
//     organisation (exclusif pour une décision, partagé pour une analyse) empêche qu'un
//     constat créé pendant une décision lui échappe.
//   - Un risque accepté échoit par le job ExpireKind, mis en file avec la décision pour
//     le lendemain du dernier jour d'acceptation à minuit UTC : une ligne « échéance »
//     d'auteur système ramène le couple « à analyser » le jour même, et l'audit le note
//     (triage.expired).
//   - Les droits (finding.triage sur le projet, triage.org pour l'organisation) sont
//     vérifiés par l'appelant ; chaque décision est journalisée (audit triage.decided,
//     triage.withdrawn, triage.expired, triage.vex_imported).
//
// VEX : Statements donne les déclarations d'un projet à exporter, Import enregistre
// celles d'un document lu par le sous-paquet vex (décisions d'auteur « vex:<source> »).
//
// Pour T15 (politiques et alertes), à réutiliser plutôt qu'à refaire :
//
//   - le statut effectif d'un constat se lit dans findings.triage_status (Status ;
//     Status.Hidden pour « non affecté » et « faux positif », masqués par défaut) ; une
//     règle qui porte sur les constats ouverts « actionnables » filtre
//     triage_status NOT IN ('not_affected', 'false_positive') ;
//   - chaque changement de statut effectif passe par Options.OnChange (Change : constat,
//     projet, avant, après, décision), appelé dans la transaction qui le produit — c'est
//     là qu'une alerte « changement de statut » se met en file (jobs.Enqueue dans tx) ;
//   - l'historique d'un constat est History ; le journal complet est triage_decisions,
//     dont chaque ligne est un événement daté et signé (author_label).
package triage
