// Package agent gère les agents, leurs jetons d'inscription et d'agent, et leurs signaux de
// vie (ADR 0014).
//
// Jetons : lotor_agt_… (agent) et lotor_enr_… (inscription d'un agent serveur), un
// identifiant public et un secret de 256 bits dont seul le SHA-256 est stocké
// (NewToken, ParseToken). Service.Authenticate résout l'organisation du jeton par
// crossorg, puis vérifie secret, révocation et expiration dans InOrg ; ses refus sont des
// *AuthError portant une clé traduisible.
//
//	p, err := agents.Authenticate(ctx, bearer)        // jeton d'agent ou d'inscription
//	res, err := agents.Enroll(ctx, p, req, ip, reqID) // agent serveur et projet de l'hôte
//	err = agents.Heartbeat(ctx, p, version)
//	projects, next, err := agents.AssignedProjects(ctx, p, cursor, limit)
//
// Côté interface : CreateRepoAgent, CreateToken, RevokeToken, Disable, CreateEnrollment,
// RevokeEnrollment, chacun journalisé dans la même transaction. Un secret n'est renvoyé
// qu'à sa création (IssuedToken.Plaintext) ; il n'est jamais stocké ni journalisé.
package agent
