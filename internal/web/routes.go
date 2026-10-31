package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"leblanc.io/open-go-sbom/internal/render"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// registerUI déclare les routes de l'interface. Les écrans des lots suivants s'y ajoutent ;
// toute route de données d'organisation vit sous /o/{slug} (le test d'isolement le vérifie).
func registerUI(r chi.Router, h *handlers, loginLimit func(http.Handler) http.Handler) {
	id := h.id
	if id == nil {
		r.Get("/", h.home)
		return
	}

	// Connexion : publiques, débit des POST borné par IP.
	r.Get(pathLogin, id.login.LoginGET)
	r.With(loginLimit).Post(pathLogin, id.login.LoginPOST)
	r.Get(pathVerify, id.mfa.VerifyGET)
	r.With(loginLimit).Post(pathVerify, id.verifyPOST)
	r.Post(pathLogout, id.logout)

	// Enrôlement du TOTP : session de configuration (premier login) ou authentifiée. mfax
	// refuse de re-provisionner un TOTP actif. La désactivation n'est pas montée : le TOTP
	// est obligatoire (seul un administrateur le réinitialise).
	r.With(requireSession).Get(pathTOTPSetup, id.mfa.SetupGET)
	r.With(requireSession).Post(pathTOTPOn, id.mfa.EnablePOST)

	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Get("/", id.home)
		r.Get("/account", id.profile)
		r.Post("/account", id.saveProfile)
		r.Get(pathTokens, id.personalTokens)
		r.Post(pathTokens, id.createPersonalToken)
		r.Post(pathTokens+"/{tokenID}/revoke", id.revokePersonalToken)
		r.Get(pathPassword, id.password)
		r.Post(pathPassword, id.changePassword)

		r.Route("/admin", func(r chi.Router) {
			r.Use(id.requireInstanceAdmin)
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			})
			r.Get("/users", id.adminUsers)
			r.Post("/users", id.createUser)
			r.Get("/users/{userID}", id.adminUser)
			r.Post("/users/{userID}/{action}", id.userAction)
			r.Get("/orgs", id.adminOrgs)
			r.Post("/orgs", id.createOrg)
			r.Get("/orgs/{slug}", id.adminOrg)
			r.Post("/orgs/{slug}/{action}", id.adminOrgAction)
			r.Get("/audit", id.adminAudit)
			r.Get("/vulndb", id.vulnDB)
		})

		r.Route("/o/{slug}", func(r chi.Router) {
			r.Use(id.orgGuard)
			r.Get("/", id.orgOverview)
			r.Get("/members", id.members)
			r.Get("/search", id.search)
			r.Get("/search/export", id.searchExport)
			r.Get("/projects", id.projects)
			r.Get("/projects/{project}", id.projectPage)
			r.Get("/projects/{project}/findings", id.findings)
			r.Get("/projects/{project}/snapshots", id.snapshots)
			r.Get("/vulnerabilities/{vulnID}", id.vulnerability)
			r.Get("/components/{componentID}", id.component)
			r.Get("/projects/{project}/snapshots/{snapshotID}", id.snapshotPage)
			r.Get("/projects/{project}/snapshots/{snapshotID}/sbom", id.downloadSBOM)
			r.Get("/agents", id.agents)
			r.Get("/agents/{agentID}", id.agentPage)
			r.With(id.requireOrgRole(tenant.RoleAnalyst)).Post("/projects/{project}/scan", id.requestScan)
			r.Group(func(r chi.Router) {
				r.Use(id.requireOrgRole(tenant.RoleAdmin))
				r.Get("/projects/new", id.newProject)
				r.Post("/projects", id.createProject)
				r.Get("/projects/{project}/settings", id.projectSettings)
				r.Post("/projects/{project}/settings", id.saveProject)
				r.Post("/projects/{project}/archive", id.setProjectArchived(true, "project_archived"))
				r.Post("/projects/{project}/unarchive", id.setProjectArchived(false, "project_unarchived"))
				r.Post("/projects/{project}/agent", id.assignAgent)
				r.Get("/agents/new", id.newAgent)
				r.Post("/agents", id.createAgent)
				r.Post("/agents/{agentID}/tokens", id.createAgentToken)
				r.Post("/agents/{agentID}/tokens/{tokenID}/revoke", id.revokeAgentToken)
				r.Post("/agents/{agentID}/disable", id.disableAgent)
				r.Get("/enrollment-tokens/new", id.newEnrollment)
				r.Post("/enrollment-tokens", id.createEnrollment)
				r.Post("/enrollment-tokens/{tokenID}/revoke", id.revokeEnrollment)
				r.Post("/members", id.addMember)
				r.Post("/members/{userID}/role", id.setMemberRole)
				r.Post("/members/{userID}/remove", id.removeMember)
				r.Get("/settings", id.orgSettings)
				r.Post("/settings", id.saveOrgSettings)
				r.Get("/audit", id.orgAudit)
			})
		})
	})
}

type handlers struct {
	renderer *render.Renderer
	id       *identity
}

type homeView struct {
	render.Page
	NoOrg bool
	Admin bool
}

func (h *handlers) home(w http.ResponseWriter, r *http.Request) {
	h.renderer.Render(w, r, http.StatusOK, "home/index", &homeView{Page: render.Page{TitleKey: "home.title"}})
}
