// Package middleware regroupe les middlewares HTTP communs aux groupes de routes
// (§ 14 de l'architecture) : identifiant de requête, journal d'accès, récupération de
// panique, en-têtes de sécurité, langue et métriques.
//
// Ordre de la chaîne de l'interface, posé par internal/web : RequestID → limitation par
// IP → AccessLog → Recover → SecurityHeaders → session (T03) → changement de mot de passe
// imposé (T03) → CSRF → Language → organisation courante (T03) → handler. Les groupes
// d'API n'ont ni session ni CSRF.
//
// Les handlers retrouvent l'identifiant de requête par RequestIDFrom et un journal qui le
// porte par Logger.
package middleware
