// Package api porte les handlers REST, qui implémentent les interfaces générées depuis
// api/openapi.yaml (internal/api/gen).
//
// MountAgent monte l'API des agents sur le routeur de /api/v1 : corps JSON borné,
// authentification par jeton (agent.Service.Authenticate), limitation par jeton
// (ratelimit d'open-go-base avec WithKeyFunc), puis le serveur strict généré. Chaque
// opération exige sa nature de jeton (requireKind) ; les erreurs sont des problèmes
// RFC 9457 traduits (internal/api/problem).
package api
