// Package org gère les organisations, leurs membres, leurs équipes et les invitations.
//
// Le rôle d'organisation vaut membre ou administrateur ; les droits sur un projet viennent
// du rôle dans son équipe (lecteur, analyste, administrateur d'équipe), selon la matrice
// de tenant (ADR 0034). Access construit le tenant.Access d'une requête : organisation et
// rôle par crossorg, rôles d'équipe sous la RLS.
//
// Un compte rejoint une organisation en acceptant une invitation (Invite, puis
// AcceptInvitation) ; la réponse à l'administrateur est la même que le compte existe ou
// non (SEC-09). Seule l'administration de l'instance ajoute directement un membre
// (AddMember). Un membre d'équipe est forcément membre de l'organisation (clé étrangère
// composite), et le retrait de l'organisation le retire de ses équipes. Une équipe qui a
// des projets ne peut pas être supprimée : tout projet a une équipe.
package org
