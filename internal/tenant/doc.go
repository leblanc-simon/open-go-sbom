// Package tenant définit l'identifiant d'organisation typé et sa propagation dans le contexte.
//
// OrgID enveloppe un UUID pour qu'une fonction de store ne puisse pas recevoir par erreur
// l'identifiant d'une autre entité : toute fonction qui touche des données d'organisation
// prend un OrgID en premier paramètre métier, et db.InOrg le déclare à PostgreSQL (RLS).
// La valeur zéro n'est jamais une organisation valide.
//
// La garde d'organisation place l'accès de la requête (Access : organisation, rôle
// d'organisation, rôles d'équipe) dans le contexte avec WithAccess.
//
// Droits (ADR 0034) : Matrix est la source unique de la matrice des droits — permission,
// portée (organisation ou équipe), rôle minimal ; Allowed l'applique, Access.Can
// l'interroge pour une ressource d'une équipe, et PermissionsDocument en écrit le
// document docs/security/permissions.md. Visibility désigne les équipes dont un compte
// voit les projets ; sa valeur zéro ne voit rien.
package tenant
