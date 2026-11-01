// Package project gère les projets (dépôts, serveurs et conteneurs des serveurs) et leurs
// références suivies.
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
//
// Un conteneur (KindContainer, T13, ADR 0040) est un projet enfant d'un serveur
// (Project.Parent), créé et tenu par l'agent de ce serveur : SightContainers enregistre,
// dans la transaction InOrg de l'API des agents, les conteneurs signalés sous le seul hôte
// confié à l'agent (création, contexte, date de signalement, retour d'un conteneur archivé
// pour absence) ; son unique référence, de nature RefContainer, porte son identité
// (Container.Key). Il garde l'équipe de son hôte par une clé étrangère en cascade
// (SetTeam le refuse pour un conteneur seul). Archiver (ArchiveAbsent, jobs de
// l'Archiver) archive les conteneurs absents depuis containers.archive_after ; un
// conteneur archivé par un utilisateur reste archivé, l'agent l'ignore. Les listes
// écartent les conteneurs sauf Filter.Containers ; Children lit ceux d'un hôte.
package project
