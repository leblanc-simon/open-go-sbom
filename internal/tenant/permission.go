package tenant

// Permission est un droit de la matrice des droits (docs/security/permissions.md, généré
// depuis Matrix par TestPermissionsDocument). Une permission d'organisation ne dépend que
// du rôle d'organisation ; une permission d'équipe porte sur une ressource d'une équipe
// (projet, agent, l'équipe elle-même) et dépend du rôle du compte dans cette équipe.
type Permission string

// Permissions d'organisation.
const (
	PermOrgView       Permission = "org.view"       // tableau de bord, recherche, exports, API, sur les projets visibles
	PermMembersView   Permission = "members.view"   // liste des membres de l'organisation
	PermMembersManage Permission = "members.manage" // inviter, changer le rôle d'organisation, retirer
	PermTeamsManage   Permission = "teams.manage"   // créer, renommer, supprimer une équipe
	PermOrgManage     Permission = "org.manage"     // paramètres et journal d'audit de l'organisation
	PermTriageOrg     Permission = "triage.org"     // décisions de triage et import de VEX pour toute l'organisation (T14)
	PermAIExternal    Permission = "ai.external"    // autoriser l'envoi du code d'un dépôt à un fournisseur de modèle externe
)

// Permissions d'équipe.
const (
	PermTeamView      Permission = "team.view"      // voir l'équipe, ses membres et ses projets
	PermTeamMembers   Permission = "team.members"   // ajouter, retirer un membre, changer son rôle d'équipe
	PermProjectView   Permission = "project.view"   // fiche, constats, instantanés, SBOM d'un projet
	PermProjectScan   Permission = "project.scan"   // demander un scan à l'agent serveur
	PermFindingTriage Permission = "finding.triage" // trier les constats d'un projet, importer un VEX pour lui (T14)
	PermProjectCreate Permission = "project.create" // créer un projet dans l'équipe
	PermProjectManage Permission = "project.manage" // modifier, archiver, réactiver, confier à un agent
	PermProjectMove   Permission = "project.move"   // rattacher à une autre équipe (droit exigé sur les deux)
	PermAgentView     Permission = "agent.view"     // voir les agents de l'équipe
	PermAgentManage   Permission = "agent.manage"   // créer un agent, ses jetons, le désactiver ; jetons d'inscription
)

// Scope dit à quoi s'applique une permission.
type Scope string

// Portées des permissions.
const (
	ScopeOrg  Scope = "org"
	ScopeTeam Scope = "team"
)

// Rule est une ligne de la matrice : la permission, sa portée, le rôle minimal qui la
// donne, et sa description (en français, reprise par le document).
type Rule struct {
	Permission  Permission
	Scope       Scope
	MinOrg      Role     // ScopeOrg : rôle d'organisation minimal
	MinTeam     TeamRole // ScopeTeam : rôle d'équipe minimal (l'administrateur d'organisation l'a toujours)
	Description string
}

// matrix est la source unique de la matrice des droits : Allowed, le document et les
// tests par route en dérivent.
var matrix = []Rule{
	{PermOrgView, ScopeOrg, RoleMember, TeamNone, "Tableau de bord, recherche, exports et API utilisateur, limités aux projets visibles"},
	{PermMembersView, ScopeOrg, RoleMember, TeamNone, "Voir la liste des membres de l'organisation"},
	{PermMembersManage, ScopeOrg, RoleAdmin, TeamNone, "Inviter un compte, changer un rôle d'organisation, retirer un membre, révoquer une invitation"},
	{PermTeamsManage, ScopeOrg, RoleAdmin, TeamNone, "Créer, renommer et supprimer une équipe"},
	{PermOrgManage, ScopeOrg, RoleAdmin, TeamNone, "Paramètres et journal d'audit de l'organisation"},
	{PermTriageOrg, ScopeOrg, RoleAdmin, TeamNone, "Décider du triage pour toute l'organisation, importer un VEX d'organisation, retirer une décision d'organisation"},
	{PermAIExternal, ScopeOrg, RoleAdmin, TeamNone, "Autoriser l'envoi du code d'un dépôt à un fournisseur de modèle externe (enrichissement IA, audité)"},
	{PermTeamView, ScopeTeam, "", TeamReader, "Voir l'équipe, ses membres et ses projets"},
	{PermTeamMembers, ScopeTeam, "", TeamAdmin, "Ajouter ou retirer un membre de l'équipe, changer son rôle d'équipe"},
	{PermProjectView, ScopeTeam, "", TeamReader, "Fiche, constats, instantanés, composants et SBOM d'un projet de l'équipe"},
	{PermProjectScan, ScopeTeam, "", TeamAnalyst, "Demander un scan à l'agent serveur d'un projet"},
	{PermFindingTriage, ScopeTeam, "", TeamAnalyst, "Trier les constats d'un projet, importer un VEX pour ce projet, retirer une décision du projet"},
	{PermProjectCreate, ScopeTeam, "", TeamAdmin, "Créer un projet dans l'équipe"},
	{PermProjectManage, ScopeTeam, "", TeamAdmin, "Modifier, archiver, réactiver un projet, le confier à un agent"},
	{PermProjectMove, ScopeTeam, "", TeamAdmin, "Rattacher un projet à une autre équipe (droit exigé dans les deux équipes)"},
	{PermAgentView, ScopeTeam, "", TeamReader, "Voir les agents de l'équipe"},
	{PermAgentManage, ScopeTeam, "", TeamAdmin, "Créer un agent de l'équipe, ses jetons, le désactiver ; jetons d'inscription de l'équipe"},
}

// Matrix renvoie la matrice des droits, dans l'ordre du document.
func Matrix() []Rule { return append([]Rule(nil), matrix...) }

// Subject est un sujet de la matrice : un rôle d'organisation et le rôle dans l'équipe de
// la ressource (TeamNone : hors de l'équipe).
type Subject struct {
	Role Role
	Team TeamRole
}

// Subjects renvoie les sujets du document, du plus au moins privilégié.
func Subjects() []Subject {
	return []Subject{
		{Role: RoleAdmin},
		{Role: RoleMember, Team: TeamAdmin},
		{Role: RoleMember, Team: TeamAnalyst},
		{Role: RoleMember, Team: TeamReader},
		{Role: RoleMember},
	}
}

func rule(p Permission) (Rule, bool) {
	for _, r := range matrix {
		if r.Permission == p {
			return r, true
		}
	}
	return Rule{}, false
}

// Allowed dit si le sujet s a la permission p. Une permission inconnue n'est jamais
// accordée ; l'administrateur d'organisation a toutes les permissions connues.
func Allowed(s Subject, p Permission) bool {
	r, ok := rule(p)
	if !ok || s.Role.rank() == 0 {
		return false
	}
	if s.Role == RoleAdmin {
		return true
	}
	if r.Scope == ScopeOrg {
		return s.Role.AtLeast(r.MinOrg)
	}
	return s.Team.AtLeast(r.MinTeam)
}
