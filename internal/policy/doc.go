// Package policy tient les politiques d'une organisation : règles déclaratives en CEL,
// évaluation, violations datées et verdict d'un instantané (T15, ADR 0045).
//
//   - Une règle (Policy) porte sur un sujet : un constat ouvert (SubjectFinding : variables
//     project, component, finding, triage, ref, now) ou un agent (SubjectAgent : agent,
//     now). Le contexte est typé (Project, Component, Finding, Triage, Ref, Agent, étiquettes
//     « cel ») : un champ inconnu, une erreur de syntaxe ou de type, un résultat non booléen
//     ou un coût estimé au-delà de MaxCost refusent la règle à l'enregistrement, avec une
//     *ExprError située (ligne, colonne). Toute évaluation est bornée par le même coût.
//   - Modèles fournis (Templates) : KEV sur un projet de production, critique avec
//     correctif disponible depuis plus de 30 jours, agent muet depuis 7 jours ; le modèle
//     « licence AGPL » reste indisponible jusqu'à l'analyse des licences (T20).
//   - Évaluation : après chaque analyse d'une référence (OnAnalyzed, point d'accroche de
//     finding.Analyzer), à chaque changement de statut de triage (OnTriageChange, point
//     d'accroche de triage.Options.OnChange), après un changement de règle (EnqueueOrg) et
//     chaque jour (Schedule) ; job policy.evaluate_project par projet, policy.evaluate_org
//     pour les agents. Une violation par couple (règle, sujet) tant qu'il satisfait la
//     règle ; elle est résolue sinon, et une nouvelle violation ne s'ouvre qu'ensuite :
//     c'est ce qui dédoublonne les notifications (notify.Queue, appelé à l'ouverture).
//   - Une règle « bloquante » rend non conforme le verdict (Verdict) d'un instantané dont
//     la référence a une violation ouverte de cette règle ; le verdict est en attente tant
//     que l'ensemble de l'instantané n'est pas celui de la dernière analyse, évaluée.
//   - Les droits (policy.manage) sont vérifiés par l'appelant ; création, modification et
//     suppression sont journalisées (policy.created, policy.updated, policy.deleted).
package policy
