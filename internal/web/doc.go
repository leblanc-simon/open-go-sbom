// Package web porte le routeur chi, les handlers HTML de l'interface, l'écoute de gestion
// et le cycle de vie des serveurs HTTP.
//
// # Groupes de routes (§ 14 de l'architecture)
//
//   - Interface : RequestID → métriques → limitation par IP → journal → récupération →
//     en-têtes de sécurité (CSP stricte, no-store) → session (T03) → changement de mot de
//     passe imposé (T03) → CSRF → langue → organisation (T03) → handler. Pages d'erreur
//     404, 405, 429 et 500 traduites, avec les mêmes en-têtes.
//   - API agent, /api/v1/agent/ : sans session ni CSRF ; jeton d'agent et limitation par
//     jeton en T04. Erreurs en application/problem+json.
//   - API utilisateur, /api/v1/orgs/{org}/ : CORS, sans CSRF de session (jeton personnel,
//     ou en-tête X-CSRF-Token pour le JavaScript de l'interface, T03/T04).
//   - Fichiers statiques, /static/<empreinte>/ : sans limitation de débit.
//
// Un écran ajoute ses routes dans le groupe de l'interface (routes.go) et son handler
// construit un modèle de vue qui embarque render.Page.
//
// # Gestion
//
// NewManagementHandler sert /healthz (le processus répond), /readyz (vérifications
// fournies : base, schéma, puis base Grype si workers.enabled en T06 ; 503 pendant
// l'arrêt) et /metrics (registre Prometheus injecté), sur une écoute séparée.
//
// # Serveurs
//
// Server écoute l'interface publique (TLS natif facultatif) et la gestion ; Run sert
// jusqu'à l'annulation du contexte (SIGTERM), puis laisse aux requêtes en cours
// http.shutdown_timeout pour finir.
package web
