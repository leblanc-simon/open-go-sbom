// Package tenant définit l'identifiant d'organisation typé et sa propagation dans le contexte.
//
// OrgID enveloppe un UUID pour qu'une fonction de store ne puisse pas recevoir par erreur
// l'identifiant d'une autre entité : toute fonction qui touche des données d'organisation
// prend un OrgID en premier paramètre métier, et db.InOrg le déclare à PostgreSQL (RLS).
// La valeur zéro n'est jamais une organisation valide.
//
// Le middleware qui résout /o/{slug} et vérifie l'appartenance arrive en T03 ; il place
// l'organisation dans le contexte avec NewContext, que les handlers relisent avec
// FromContext.
package tenant
