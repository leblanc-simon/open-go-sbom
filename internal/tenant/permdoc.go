package tenant

import (
	"fmt"
	"strings"
)

// subjectLabel nomme un sujet dans le document.
func subjectLabel(s Subject) string {
	if s.Role == RoleAdmin {
		return "Administrateur d'organisation"
	}
	switch s.Team {
	case TeamAdmin:
		return "Administrateur d'équipe"
	case TeamAnalyst:
		return "Analyste"
	case TeamReader:
		return "Lecteur"
	}
	return "Membre hors de l'équipe"
}

// PermissionsDocument écrit la matrice des droits en Markdown. docs/security/permissions.md
// en est la sortie exacte : TestPermissionsDocument échoue si le fichier diffère, et
// `go test ./internal/tenant -run TestPermissionsDocument -update` le régénère.
func PermissionsDocument() string {
	var b strings.Builder
	b.WriteString(`# Matrice des droits

<!-- Fichier généré depuis internal/tenant/permission.go : ne pas le modifier à la main.
     go test ./internal/tenant -run TestPermissionsDocument -update -->

Qui voit, trie et modifie quoi dans une organisation (T16, ADR 0034). Le rôle
d'organisation vaut **membre** ou **administrateur** ; les droits sur un projet, un agent ou
une équipe viennent du rôle du compte **dans l'équipe de la ressource** : lecteur, analyste
ou administrateur d'équipe. L'administrateur d'organisation voit et gère tout.

Cette matrice est la source des contrôles de l'application (` + "`tenant.Allowed`" + `) et des tests
par route (` + "`internal/web`" + `, test ` + "`TestRoutePermissionsFollowMatrix`" + `) : document, code et tests
dérivent de la même table.

## Règles de visibilité

- Un membre ne voit que les projets des équipes dont il est membre, quel que soit son
  rôle d'équipe ; un membre sans équipe ne voit aucun projet.
- Le filtre s'applique à toutes les surfaces de lecture : listes, fiches, recherche et ses
  exports, tableau de bord et ses statistiques, pages des vulnérabilités et des
  composants, API utilisateur (jetons personnels compris), agents.
- Une ressource d'une équipe invisible répond **404**, comme une ressource d'une autre
  organisation ; une action refusée sur une ressource visible répond **403**.
- Un agent sans équipe (agent d'organisation) n'est visible et géré que par les
  administrateurs d'organisation ; il peut servir les projets de toutes les équipes.
- Les projets créés par un jeton d'inscription héritent de l'équipe du jeton, et l'agent
  inscrit aussi.
- Un compte devient membre d'une organisation en acceptant une invitation ; la réponse à
  l'invitation est la même, que le compte existe ou non.

## Matrice

`)
	subjects := Subjects()
	b.WriteString("| Permission | Portée | Description |")
	for _, s := range subjects {
		b.WriteString(" " + subjectLabel(s) + " |")
	}
	b.WriteString("\n| --- | --- | --- |")
	for range subjects {
		b.WriteString(" :---: |")
	}
	b.WriteString("\n")
	for _, r := range matrix {
		scope := "organisation"
		if r.Scope == ScopeTeam {
			scope = "équipe"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |", r.Permission, scope, r.Description)
		for _, s := range subjects {
			mark := "—"
			if Allowed(s, r.Permission) {
				mark = "oui"
			}
			b.WriteString(" " + mark + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString(`
Pour une permission d'organisation, les colonnes des rôles d'équipe valent pour tout
membre qui n'est pas administrateur d'organisation.
`)
	return b.String()
}
