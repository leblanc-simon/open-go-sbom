// Package project gère les projets (dépôts et serveurs) et leurs références suivies.
//
// Un dépôt suit des branches et des étiquettes git et peut être confié à un agent dépôt ;
// un serveur suit une seule référence, son nom d'hôte, et reçoit son agent à
// l'inscription (CreateHost, dans la transaction de l'inscription). Une référence retirée
// garde sa ligne (removed_at) pour que l'historique de ses instantanés survive.
//
// Pour l'API des agents, ListForAgent et RefForAgent travaillent dans la transaction
// InOrg de l'appelant et ne voient que les projets actifs confiés à l'agent :
// RefForAgent est le contrôle d'écriture d'un envoi (T05).
//
// Tout projet appartient à une équipe (TeamID, ADR 0034) : Get et List ne voient que les
// projets des équipes visibles (db.Visible) ; SetTeam rattache un projet à une autre
// équipe, et un agent d'équipe ne se confie qu'aux projets de son équipe.
package project
