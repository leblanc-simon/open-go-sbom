//go:build integration

package agent_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// clock est une horloge de test qui n'avance que sur demande.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	tdb      *dbtest.DB
	clock    *clock
	agents   *agent.Service
	projects *project.Service
	orgs     *org.Service
	actor    audit.Actor
}

func setup(t *testing.T) fixture {
	t.Helper()
	tdb := dbtest.New(t)
	u, _, err := account.NewService(tdb.App, 4).Create(context.Background(), audit.System, "admin@example.org", false)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Now().UTC().Truncate(time.Microsecond)}
	return fixture{tdb: tdb, clock: c, agents: agent.NewService(tdb.App, agent.WithClock(c.Now)),
		projects: project.NewService(tdb.App), orgs: org.NewService(tdb.App), actor: audit.Actor{UserID: u.ID, Email: u.Email}}
}

func (f fixture) org(t *testing.T, slug string) tenant.OrgID {
	t.Helper()
	o, err := f.orgs.Create(context.Background(), audit.System, slug, "Org "+slug, "fr", f.actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

func (f fixture) enrollment(t *testing.T, org tenant.OrgID, in agent.EnrollmentInput) string {
	t.Helper()
	if in.Name == "" {
		in.Name = "parc"
	}
	if in.LifetimeHours == 0 {
		in.LifetimeHours = 24
	}
	if in.MaxUses == 0 {
		in.MaxUses = 5
	}
	_, issued, err := f.agents.CreateEnrollment(context.Background(), f.actor, org, f.enrollTeam(t, org, in))
	if err != nil {
		t.Fatal(err)
	}
	return issued.Plaintext
}

func (f fixture) enroll(t *testing.T, token, host string) (agent.Enrollment, error) {
	t.Helper()
	ctx := context.Background()
	p, err := f.agents.Authenticate(ctx, token)
	if err != nil {
		return agent.Enrollment{}, err
	}
	return f.agents.Enroll(ctx, p, agent.EnrollRequest{Hostname: host, Version: "1.0.0"}, "192.0.2.1", "req-1")
}

func authKey(err error) string {
	var ae *agent.AuthError
	if errors.As(err, &ae) {
		return ae.Key
	}
	var ce *agent.ConflictError
	if errors.As(err, &ce) {
		return ce.Key
	}
	return ""
}

func (f fixture) actions(t *testing.T, org tenant.OrgID) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	if err := f.tdb.App.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		page, err := audit.ListOrg(context.Background(), tx, "", 200)
		out = page.Items
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEnrollmentCreatesHostProject : l'inscription d'un hôte crée son projet avec les
// étiquettes du jeton, le confie au nouvel agent et renvoie un jeton d'agent utilisable.
func TestEnrollmentCreatesHostProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	enr := f.enrollment(t, o, agent.EnrollmentInput{Labels: project.Labels{"env": "prod"}, MaxUses: 2})

	res, err := f.enroll(t, enr, "SRV-DB-02")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Project.Slug != "srv-db-02" || res.Agent.Kind != agent.KindHost || res.Agent.Name != "srv-db-02" {
		t.Fatalf("inscription : %+v", res)
	}
	p, err := f.projects.Get(ctx, o, tenant.AllTeams(), "srv-db-02")
	if err != nil || p.Kind != project.KindHost || p.HostRef() != "srv-db-02" || p.Labels["env"] != "prod" ||
		p.Agent == nil || p.Agent.ID != res.Agent.ID {
		t.Fatalf("projet de l'hôte : %+v %v", p, err)
	}
	principal, err := f.agents.Authenticate(ctx, res.Token.Plaintext)
	if err != nil || principal.Kind != agent.KindAgent || principal.AgentID != res.Agent.ID || principal.Org != o {
		t.Fatalf("jeton d'agent : %+v %v", principal, err)
	}
	projects, next, err := f.agents.AssignedProjects(ctx, principal, "", 10)
	if err != nil || next != "" || len(projects) != 1 || projects[0].ID != p.ID || projects[0].HostRef() != "srv-db-02" {
		t.Fatalf("projets confiés : %+v %q %v", projects, next, err)
	}

	// Seconde inscription du même hôte : refusée tant que l'agent est actif.
	if _, err := f.enroll(t, enr, "srv-db-02"); authKey(err) != agent.KeyHostTaken {
		t.Fatalf("hôte déjà suivi : %v", err)
	}
	// Désactivé, l'agent libère l'hôte : la réinscription rattache le projet existant.
	if err := f.agents.Disable(ctx, f.actor, o, res.Agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.Authenticate(ctx, res.Token.Plaintext); authKey(err) != agent.KeyTokenRevokedErr {
		t.Fatalf("jeton d'un agent désactivé : %v", err)
	}
	again, err := f.enroll(t, enr, "srv-db-02")
	if err != nil || again.Created || again.Project.ID != p.ID {
		t.Fatalf("réinscription : %+v %v", again, err)
	}
	// Deux usages consommés : le jeton est épuisé (l'échec n'a pas consommé d'usage).
	if _, err := f.enroll(t, enr, "srv-03"); authKey(err) != agent.KeyEnrollmentExhausted {
		t.Fatalf("jeton épuisé : %v", err)
	}

	var enrolled, created int
	for _, e := range f.actions(t, o) {
		switch e.Action {
		case audit.AgentEnrolled:
			enrolled++
			if e.ActorUserID != 0 || e.IP != "192.0.2.1" || e.ActorEmail == "" {
				t.Errorf("auteur de l'inscription : %+v", e)
			}
		case audit.ProjectCreated:
			created++
		}
	}
	if enrolled != 2 || created != 1 {
		t.Errorf("journal : %d inscriptions, %d créations", enrolled, created)
	}
}

// TestEnrollmentTokenRefusals : jeton expiré, révoqué, mal formé, faux secret, d'une
// organisation archivée : refusés avec une clé traduisible, sans rien créer.
func TestEnrollmentTokenRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	expiring := f.enrollment(t, o, agent.EnrollmentInput{LifetimeHours: 1})
	revoked := f.enrollment(t, o, agent.EnrollmentInput{Name: "à révoquer"})
	list, err := f.agents.Enrollments(ctx, o, tenant.AllTeams())
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	for _, e := range list {
		if e.Name == "à révoquer" {
			if err := f.agents.RevokeEnrollment(ctx, f.actor, o, e.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.agents.RevokeEnrollment(ctx, f.actor, o, e.ID); err == nil {
				t.Error("double révocation acceptée")
			}
		}
	}
	f.clock.advance(time.Hour)
	if _, err := f.enroll(t, expiring, "srv"); authKey(err) != agent.KeyTokenExpired {
		t.Errorf("expiré : %v", err)
	}
	if _, err := f.enroll(t, revoked, "srv"); authKey(err) != agent.KeyTokenRevokedErr {
		t.Errorf("révoqué : %v", err)
	}
	wrong := expiring[:len(expiring)-4] + "aaaa"
	if wrong == expiring {
		wrong = expiring[:len(expiring)-4] + "bbbb"
	}
	for name, tok := range map[string]string{"faux secret": wrong, "mal formé": "lotor_enr_x", "vide": "", "inconnu": mustToken(t, agent.KindEnrollment)} {
		if _, err := f.enroll(t, tok, "srv"); authKey(err) != agent.KeyTokenInvalid {
			t.Errorf("%s : %v", name, err)
		}
	}
	// Un jeton d'inscription n'est pas un jeton d'agent, et inversement.
	if p, err := f.agents.Authenticate(ctx, expiring); err == nil {
		if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "1"}); authKey(err) != agent.KeyTokenInvalid {
			t.Errorf("signal de vie avec un jeton d'inscription : %v", err)
		}
	}
	page, err := f.projects.List(ctx, o, tenant.AllTeams(), project.Filter{}, "", 10)
	if err != nil || len(page.Items) != 0 {
		t.Errorf("projets créés malgré les refus : %v %v", page.Items, err)
	}

	// Organisation archivée : ses jetons ne valent plus rien.
	live := f.enrollment(t, o, agent.EnrollmentInput{})
	if err := f.orgs.SetArchived(ctx, audit.System, o, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.enroll(t, live, "srv"); authKey(err) != agent.KeyTokenInvalid {
		t.Errorf("organisation archivée : %v", err)
	}
}

func mustToken(t *testing.T, kind agent.TokenKind) string {
	t.Helper()
	tok, err := agent.NewToken(kind)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Plaintext
}

// TestEnrollmentIntoDesignatedProject : un jeton qui désigne un projet de serveur y
// rattache l'agent ; le projet déjà pourvu d'un agent actif est refusé.
func TestEnrollmentIntoDesignatedProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	h, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, project.Input{Kind: project.KindHost, Name: "Base de prod", HostRef: "db-prod"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.CreateEnrollment(ctx, f.actor, o, f.enrollTeam(t, o, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1, ProjectSlug: "absent"})); err == nil {
		t.Error("projet inconnu accepté")
	}
	r, err := f.projects.Create(ctx, f.actor, o, f.inTeam(t, o, project.Input{Kind: project.KindRepo, Name: "depot", Branches: []string{"main"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.CreateEnrollment(ctx, f.actor, o, f.enrollTeam(t, o, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1, ProjectSlug: r.Slug})); err == nil {
		t.Error("dépôt accepté comme projet de serveur")
	}
	tok := f.enrollment(t, o, agent.EnrollmentInput{ProjectSlug: h.Slug, MaxUses: 2})
	res, err := f.enroll(t, tok, "db-prod-01")
	if err != nil || res.Created || res.Project.ID != h.ID {
		t.Fatalf("rattachement : %+v %v", res, err)
	}
	if _, err := f.enroll(t, tok, "db-prod-02"); authKey(err) != agent.KeyHostTaken {
		t.Errorf("projet déjà pourvu : %v", err)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, h.Slug, true); err != nil {
		t.Fatal(err)
	}
	if err := f.agents.Disable(ctx, f.actor, o, res.Agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.enroll(t, tok, "db-prod-03"); authKey(err) != agent.KeyProjectUnavailable {
		t.Errorf("projet archivé : %v", err)
	}
}

// TestAgentTokenLifecycle : création, dernier usage, révocation immédiate, expiration,
// rotation.
func TestAgentTokenLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	a, first, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci", "initial", 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "CI", "initial", 30); !isKey(err, agent.KeyNameTaken) {
		t.Errorf("nom en double : %v", err)
	}
	if _, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "autre", "initial", 7); !isKey(err, agent.KeyExpiryInvalid) {
		t.Errorf("durée non proposée : %v", err)
	}
	p, err := f.agents.Authenticate(ctx, first.Plaintext)
	if err != nil || p.AgentKind != agent.KindRepo {
		t.Fatalf("premier jeton : %+v %v", p, err)
	}
	if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "0.9.2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.Heartbeat(ctx, p, agent.HeartbeatRequest{Version: "avec espace"}); !isKey(err, agent.KeyVersionInvalid) {
		t.Errorf("version invalide : %v", err)
	}
	got, err := f.agents.Get(ctx, o, tenant.AllTeams(), a.ID)
	if err != nil || got.Version != "0.9.2" || got.LastSeenAt == nil || got.ActiveTokens != 1 || len(got.Tokens) != 1 ||
		got.Tokens[0].LastUsedAt == nil || got.Tokens[0].CreatedBy != "admin@example.org" {
		t.Fatalf("agent : %+v %v", got, err)
	}
	if got.StateAt(f.clock.Now()) != agent.StateActive {
		t.Errorf("état : %s", got.StateAt(f.clock.Now()))
	}

	// Rotation : un second jeton, puis révocation du premier, effective à la requête
	// suivante.
	second, secondIssued, err := f.agents.CreateToken(ctx, f.actor, o, a.ID, "rotation", 0)
	if err != nil || second.ExpiresAt != nil {
		t.Fatalf("second jeton : %+v %v", second, err)
	}
	if err := f.agents.RevokeToken(ctx, f.actor, o, a.ID, got.Tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agents.Authenticate(ctx, first.Plaintext); authKey(err) != agent.KeyTokenRevokedErr {
		t.Errorf("jeton révoqué : %v", err)
	}
	if err := f.agents.RevokeToken(ctx, f.actor, o, a.ID, got.Tokens[0].ID); !isKey(err, agent.KeyTokenRevoked) {
		t.Errorf("double révocation : %v", err)
	}
	if _, err := f.agents.Authenticate(ctx, secondIssued.Plaintext); err != nil {
		t.Errorf("second jeton : %v", err)
	}

	// Expiration : un jeton de 30 jours est refusé au-delà.
	_, third, err := f.agents.CreateToken(ctx, f.actor, o, a.ID, "court", 30)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(30*24*time.Hour + time.Second)
	if _, err := f.agents.Authenticate(ctx, third.Plaintext); authKey(err) != agent.KeyTokenExpired {
		t.Errorf("jeton expiré : %v", err)
	}
	if got, _ := f.agents.Get(ctx, o, tenant.AllTeams(), a.ID); got.StateAt(f.clock.Now()) != agent.StateSilent {
		t.Errorf("agent muet attendu : %s", got.StateAt(f.clock.Now()))
	}

	// Désactivé : plus de jeton, plus de création.
	if err := f.agents.Disable(ctx, f.actor, o, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.CreateToken(ctx, f.actor, o, a.ID, "x", 30); !isKey(err, agent.KeyAgentDisabled) {
		t.Errorf("jeton d'un agent désactivé : %v", err)
	}
	if _, err := f.agents.Authenticate(ctx, secondIssued.Plaintext); authKey(err) != agent.KeyTokenRevokedErr {
		t.Errorf("jeton d'un agent désactivé : %v", err)
	}
	page, err := f.agents.List(ctx, o, tenant.AllTeams(), agent.Filter{Disabled: true}, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].StateAt(f.clock.Now()) != agent.StateDisabled {
		t.Errorf("agents désactivés : %+v %v", page.Items, err)
	}

	counts := map[audit.Action]int{}
	for _, e := range f.actions(t, o) {
		counts[e.Action]++
		for _, v := range e.Details {
			for _, secret := range []string{first.Plaintext, secondIssued.Plaintext, third.Plaintext} {
				if v == secret {
					t.Error("un secret de jeton figure au journal")
				}
			}
		}
	}
	if counts[audit.AgentCreated] != 1 || counts[audit.AgentTokenCreated] != 3 || counts[audit.AgentTokenRevoked] != 1 || counts[audit.AgentDisabled] != 1 {
		t.Errorf("journal : %v", counts)
	}
}

func isKey(err error, k string) bool {
	v, ok := account.IsValidation(err)
	return ok && v.Key == k
}

// TestAgentSeesOnlyItsProjects : un agent ne voit et ne peut écrire que les projets
// actifs qui lui sont confiés, jamais ceux d'un autre agent ni d'une autre organisation.
func TestAgentSeesOnlyItsProjects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o, other := f.org(t, "a"), f.org(t, "b")
	a1, tok1, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci-1", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	a2, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci-2", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	b1, tokB, err := f.agents.CreateRepoAgent(ctx, f.actor, other, nil, "ci-1", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(org tenant.OrgID, name string, agentID *agent.Agent) project.Project {
		p, err := f.projects.Create(ctx, f.actor, org, f.inTeam(t, org, project.Input{Kind: project.KindRepo, Name: name, Branches: []string{"main"}}))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.projects.AssignAgent(ctx, f.actor, org, p.Slug, &agentID.ID); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var mine []project.Project
	for _, n := range []string{"p1", "p2", "p3"} {
		mine = append(mine, mk(o, n, &a1))
	}
	theirs := mk(o, "p-autre", &a2)
	foreign := mk(other, "p-b", &b1)
	if err := f.projects.SetArchived(ctx, f.actor, o, "p3", true); err != nil {
		t.Fatal(err)
	}

	p, err := f.agents.Authenticate(ctx, tok1.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	first, next, err := f.agents.AssignedProjects(ctx, p, "", 1)
	if err != nil || len(first) != 1 || next == "" {
		t.Fatalf("première page : %v %q %v", first, next, err)
	}
	rest, last, err := f.agents.AssignedProjects(ctx, p, next, 10)
	if err != nil || len(rest) != 1 || last != "" {
		t.Fatalf("seconde page : %v %q %v", rest, last, err)
	}
	seen := map[string]bool{first[0].Slug: true, rest[0].Slug: true}
	if !seen["p1"] || !seen["p2"] {
		t.Errorf("projets vus : %v", seen)
	}

	err = f.tdb.App.InOrg(ctx, p.Org, func(tx *db.OrgTx) error {
		if _, err := project.RefForAgent(ctx, tx, a1.ID, mine[0].ID, project.RefBranch, "main"); err != nil {
			t.Errorf("référence confiée : %v", err)
		}
		for name, c := range map[string]struct {
			pid  uuid.UUID
			kind project.RefKind
			ref  string
		}{
			"projet d'un autre agent": {theirs.ID, project.RefBranch, "main"},
			"projet archivé":          {mine[2].ID, project.RefBranch, "main"},
			"autre organisation":      {foreign.ID, project.RefBranch, "main"},
			"référence non suivie":    {mine[0].ID, project.RefBranch, "dev"},
			"autre nature":            {mine[0].ID, project.RefTag, "main"},
		} {
			if _, err := project.RefForAgent(ctx, tx, a1.ID, c.pid, c.kind, c.ref); !errors.Is(err, project.ErrNotFound) {
				t.Errorf("%s : %v", name, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	pb, err := f.agents.Authenticate(ctx, tokB.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	other1, _, err := f.agents.AssignedProjects(ctx, pb, "", 10)
	if err != nil || len(other1) != 1 || other1[0].ID != foreign.ID {
		t.Errorf("agent de B : %v %v", other1, err)
	}
}

// TestListsAndValidation : listes bornées et filtrées, curseurs, saisies refusées.
func TestListsAndValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	for _, n := range []string{"zulu", "Alpha", "mike"} {
		if _, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, n, "initial", 90); err != nil {
			t.Fatal(err)
		}
	}
	enr := f.enrollment(t, o, agent.EnrollmentInput{})
	if _, err := f.enroll(t, enr, "host-1"); err != nil {
		t.Fatal(err)
	}
	names := func(fl agent.Filter, cursor string, limit int) ([]string, string) {
		page, err := f.agents.List(ctx, o, tenant.AllTeams(), fl, cursor, limit)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range page.Items {
			out = append(out, a.Name)
		}
		return out, page.NextCursor
	}
	first, next := names(agent.Filter{}, "", 2)
	if len(first) != 2 || first[0] != "Alpha" || first[1] != "host-1" || next == "" {
		t.Fatalf("première page : %v %q", first, next)
	}
	if rest, last := names(agent.Filter{}, next, 2); len(rest) != 2 || rest[0] != "mike" || last != "" {
		t.Fatalf("seconde page : %v %q", rest, last)
	}
	if hosts, _ := names(agent.Filter{Kind: agent.KindHost}, "", 10); len(hosts) != 1 || hosts[0] != "host-1" {
		t.Errorf("agents serveur : %v", hosts)
	}
	if _, err := f.agents.List(ctx, o, tenant.AllTeams(), agent.Filter{}, "x", 10); !errors.Is(err, pagination.ErrInvalidCursor) {
		t.Errorf("curseur : %v", err)
	}
	var le *pagination.LimitError
	if _, err := f.agents.List(ctx, o, tenant.AllTeams(), agent.Filter{}, "", 201); !errors.As(err, &le) {
		t.Errorf("taille : %v", err)
	}
	repos, err := f.agents.RepoAgents(ctx, o, f.defaultTeam(t, o))
	if err != nil || len(repos) != 3 {
		t.Errorf("agents dépôt : %v %v", repos, err)
	}

	// Jetons d'inscription : les utilisables d'abord.
	spent := f.enrollment(t, o, agent.EnrollmentInput{Name: "unique", MaxUses: 1})
	if _, err := f.enroll(t, spent, "host-2"); err != nil {
		t.Fatal(err)
	}
	list, err := f.agents.Enrollments(ctx, o, tenant.AllTeams())
	if err != nil || len(list) != 2 || list[0].Name != "parc" || !list[0].UsableAt(f.clock.Now()) || list[1].UsableAt(f.clock.Now()) ||
		list[1].Uses != 1 || list[1].LastUsedAt == nil || list[0].Prefix() == "" || list[0].CreatedBy != "admin@example.org" {
		t.Fatalf("jetons d'inscription : %+v %v", list, err)
	}

	for name, in := range map[string]struct {
		in  agent.EnrollmentInput
		key string
	}{
		"nom vide":           {agent.EnrollmentInput{Name: " ", LifetimeHours: 24, MaxUses: 1}, agent.KeyNameInvalid},
		"durée non proposée": {agent.EnrollmentInput{Name: "x", LifetimeHours: 2, MaxUses: 1}, agent.KeyExpiryInvalid},
		"aucun usage":        {agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 0}, agent.KeyMaxUsesInvalid},
		"trop d'usages":      {agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 10001}, agent.KeyMaxUsesInvalid},
		"étiquette invalide": {agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1, Labels: project.Labels{"A": ""}}, project.KeyLabelInvalid},
		"projet inexistant":  {agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1, ProjectSlug: "absent"}, agent.KeyProjectNotHost},
	} {
		if _, _, err := f.agents.CreateEnrollment(ctx, f.actor, o, f.enrollTeam(t, o, in.in)); !isKey(err, in.key) {
			t.Errorf("%s : %v", name, err)
		}
	}
	if _, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ok", "", 90); !isKey(err, agent.KeyNameInvalid) {
		t.Errorf("nom de jeton vide : %v", err)
	}
	if _, _, err := f.agents.CreateToken(ctx, f.actor, o, repos[0].ID, "x", 7); !isKey(err, agent.KeyExpiryInvalid) {
		t.Errorf("durée de jeton : %v", err)
	}
	unknown := uuid.Must(uuid.NewV7())
	if _, err := f.agents.Get(ctx, o, tenant.AllTeams(), unknown); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("agent inconnu : %v", err)
	}
	if err := f.agents.RevokeToken(ctx, f.actor, o, repos[0].ID, unknown); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("jeton inconnu : %v", err)
	}
	if err := f.agents.RevokeEnrollment(ctx, f.actor, o, unknown); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("jeton d'inscription inconnu : %v", err)
	}
	if err := f.agents.Disable(ctx, f.actor, o, unknown); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("désactivation d'un agent inconnu : %v", err)
	}
	if err := f.agents.Disable(ctx, f.actor, o, repos[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.agents.Disable(ctx, f.actor, o, repos[0].ID); err != nil {
		t.Errorf("seconde désactivation : %v", err)
	}
	// Un nom libéré par un agent désactivé peut resservir.
	if _, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, repos[0].Name, "initial", 90); err != nil {
		t.Errorf("nom d'un agent désactivé : %v", err)
	}

	// Projets confiés : bornes de la page et curseur.
	tok, err := f.agents.Authenticate(ctx, mustEnroll(t, f, o))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.AssignedProjects(ctx, tok, "", 0); !errors.As(err, &le) {
		t.Errorf("taille nulle : %v", err)
	}
	if _, _, err := f.agents.AssignedProjects(ctx, tok, "x", 10); !errors.Is(err, pagination.ErrInvalidCursor) {
		t.Errorf("curseur : %v", err)
	}
	enrPrincipal, err := f.agents.Authenticate(ctx, enr)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.AssignedProjects(ctx, enrPrincipal, "", 10); authKey(err) != agent.KeyTokenInvalid {
		t.Errorf("projets avec un jeton d'inscription : %v", err)
	}
	// Instantanés courants : aucun avant le premier envoi (T05), refus d'un jeton
	// d'inscription.
	projects, _, err := f.agents.AssignedProjects(ctx, tok, "", 10)
	if err != nil || len(projects) != 1 || len(projects[0].Refs) != 1 {
		t.Fatalf("projets %+v, %v", projects, err)
	}
	if cur, err := f.agents.CurrentSnapshots(ctx, tok, []uuid.UUID{projects[0].Refs[0].ID}); err != nil || len(cur) != 0 {
		t.Errorf("instantanés courants %v, %v", cur, err)
	}
	if _, err := f.agents.CurrentSnapshots(ctx, enrPrincipal, nil); authKey(err) != agent.KeyTokenInvalid {
		t.Errorf("instantanés avec un jeton d'inscription : %v", err)
	}
	if _, err := f.agents.Enroll(ctx, tok, agent.EnrollRequest{Hostname: "h", Version: "1"}, "", ""); authKey(err) != agent.KeyTokenInvalid {
		t.Errorf("inscription avec un jeton d'agent : %v", err)
	}
	if _, err := f.agents.Enroll(ctx, enrPrincipal, agent.EnrollRequest{Hostname: "h", Version: "a b"}, "", ""); !isKey(err, agent.KeyVersionInvalid) {
		t.Errorf("version invalide : %v", err)
	}
}

// mustEnroll inscrit un hôte neuf et renvoie son jeton d'agent.
func mustEnroll(t *testing.T, f fixture, o tenant.OrgID) string {
	t.Helper()
	res, err := f.enroll(t, f.enrollment(t, o, agent.EnrollmentInput{Name: "x"}), "host-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	return res.Token.Plaintext
}

// inTeam rattache une saisie sans équipe à l'équipe créée avec l'organisation.
func (f fixture) inTeam(t *testing.T, org tenant.OrgID, in project.Input) project.Input {
	t.Helper()
	if in.TeamID == uuid.Nil {
		in.TeamID = f.defaultTeam(t, org)
	}
	return in
}

// enrollTeam fait de même pour un jeton d'inscription.
func (f fixture) enrollTeam(t *testing.T, org tenant.OrgID, in agent.EnrollmentInput) agent.EnrollmentInput {
	t.Helper()
	if in.TeamID == uuid.Nil {
		in.TeamID = f.defaultTeam(t, org)
	}
	return in
}

// defaultTeam renvoie l'équipe créée avec l'organisation (DefaultTeamName).
func (f fixture) defaultTeam(t *testing.T, org tenant.OrgID) uuid.UUID {
	t.Helper()
	teams, err := f.orgs.Teams(context.Background(), org, tenant.AllTeams())
	if err != nil || len(teams) == 0 {
		t.Fatalf("équipes : %v, %v", teams, err)
	}
	return teams[0].ID
}

// TestEnrollmentInheritsTheTokenTeam : le projet créé et l'agent inscrit prennent l'équipe
// du jeton d'inscription ; rattaché à un projet existant, l'agent prend l'équipe du
// projet, qui doit être celle du jeton. Les listes et fiches ne montrent que les agents
// et jetons des équipes visibles ; un agent d'organisation n'est visible que de toutes
// les équipes.
func TestEnrollmentInheritsTheTokenTeam(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	general := f.defaultTeam(t, o)
	web, err := f.orgs.CreateTeam(ctx, f.actor, o, "Web")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.CreateEnrollment(ctx, f.actor, o, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1}); !isKey(err, agent.KeyTeamInvalid) {
		t.Fatalf("jeton sans équipe : %v", err)
	}
	if _, _, err := f.agents.CreateEnrollment(ctx, f.actor, o, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1,
		TeamID: uuid.Must(uuid.NewV7())}); !isKey(err, agent.KeyTeamInvalid) {
		t.Fatalf("équipe inconnue : %v", err)
	}
	enr, err := f.enroll(t, f.enrollment(t, o, agent.EnrollmentInput{TeamID: web.ID}), "srv-web")
	if err != nil {
		t.Fatal(err)
	}
	if !enr.Created || enr.Agent.TeamID == nil || *enr.Agent.TeamID != web.ID {
		t.Fatalf("inscription : %+v", enr)
	}
	p, err := f.projects.Get(ctx, o, tenant.OnlyTeams(web.ID), enr.Project.Slug)
	if err != nil || p.TeamID != web.ID {
		t.Fatalf("projet de l'hôte : %+v, %v", p, err)
	}
	// Projet existant d'une autre équipe : le jeton doit être de la même équipe.
	h, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "db", HostRef: "db", TeamID: general})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.agents.CreateEnrollment(ctx, f.actor, o, agent.EnrollmentInput{Name: "x", LifetimeHours: 24, MaxUses: 1,
		ProjectSlug: h.Slug, TeamID: web.ID}); !isKey(err, agent.KeyTeamMismatch) {
		t.Fatalf("projet d'une autre équipe : %v", err)
	}
	attached, err := f.enroll(t, f.enrollment(t, o, agent.EnrollmentInput{TeamID: general, ProjectSlug: h.Slug}), "db")
	if err != nil || attached.Created || attached.Agent.TeamID == nil || *attached.Agent.TeamID != general {
		t.Fatalf("rattachement : %+v, %v", attached, err)
	}
	orgAgent, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, nil, "ci", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	// Visibilité : un membre de Web voit son agent et son jeton, pas les autres.
	vis := tenant.OnlyTeams(web.ID)
	page, err := f.agents.List(ctx, o, vis, agent.Filter{}, "", 50)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != enr.Agent.ID || page.Items[0].TeamName != "Web" {
		t.Fatalf("agents visibles : %+v, %v", page.Items, err)
	}
	if all, _ := f.agents.List(ctx, o, tenant.AllTeams(), agent.Filter{}, "", 50); len(all.Items) != 3 {
		t.Fatalf("agents de l'administrateur : %d", len(all.Items))
	}
	if _, err := f.agents.Get(ctx, o, vis, orgAgent.ID); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("agent d'organisation vu d'une équipe : %v", err)
	}
	if _, err := f.agents.Team(ctx, o, vis, attached.Agent.ID); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("agent d'une autre équipe : %v", err)
	}
	if team, err := f.agents.Team(ctx, o, tenant.AllTeams(), orgAgent.ID); err != nil || team != nil {
		t.Fatalf("équipe d'un agent d'organisation : %v, %v", team, err)
	}
	tokens, err := f.agents.Enrollments(ctx, o, vis)
	if err != nil || len(tokens) != 1 || tokens[0].TeamID != web.ID {
		t.Fatalf("jetons visibles : %+v, %v", tokens, err)
	}
	if team, err := f.agents.EnrollmentTeam(ctx, o, tokens[0].ID); err != nil || team != web.ID {
		t.Fatalf("équipe du jeton : %v, %v", team, err)
	}
	if repos, err := f.agents.RepoAgents(ctx, o, web.ID); err != nil || len(repos) != 1 || repos[0].ID != orgAgent.ID {
		t.Fatalf("agents dépôt utilisables par Web : %+v, %v", repos, err)
	}
	// Une équipe supprimée rend ses agents à l'organisation et emporte ses jetons.
	empty, _ := f.orgs.CreateTeam(ctx, f.actor, o, "Vide")
	teamAgent, _, err := f.agents.CreateRepoAgent(ctx, f.actor, o, &empty.ID, "ci-vide", "initial", 90)
	if err != nil {
		t.Fatal(err)
	}
	f.enrollment(t, o, agent.EnrollmentInput{TeamID: empty.ID})
	if err := f.orgs.DeleteTeam(ctx, f.actor, o, empty.ID); err != nil {
		t.Fatal(err)
	}
	if team, err := f.agents.Team(ctx, o, tenant.AllTeams(), teamAgent.ID); err != nil || team != nil {
		t.Fatalf("agent après suppression de son équipe : %v, %v", team, err)
	}
	if all, _ := f.agents.Enrollments(ctx, o, tenant.AllTeams()); len(all) != 2 {
		t.Fatalf("jetons après suppression d'une équipe : %d", len(all))
	}
}

// TestEnrollmentByHostnameStaysInTheTokenTeam : SEC2-02. Sans projet désigné, un jeton
// d'inscription d'une équipe ne prend pas, par le seul nom d'hôte déclaré, le projet hôte
// d'une autre équipe (sans agent, avec agent ou archivé) : la réponse est celle d'un hôte
// déjà suivi, le projet reste intact. Dans l'équipe du jeton, le rattachement par le nom
// fonctionne toujours ; un projet désigné passé dans une autre équipe n'est plus confié.
func TestEnrollmentByHostnameStaysInTheTokenTeam(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := setup(t)
	o := f.org(t, "a")
	general := f.defaultTeam(t, o)
	web, err := f.orgs.CreateTeam(ctx, f.actor, o, "Web")
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "db-prod", HostRef: "db-prod", TeamID: general})
	if err != nil {
		t.Fatal(err)
	}
	webToken := func() string { return f.enrollment(t, o, agent.EnrollmentInput{TeamID: web.ID}) }
	if _, err := f.enroll(t, webToken(), "db-prod"); authKey(err) != agent.KeyHostTaken {
		t.Fatalf("hôte sans agent d'une autre équipe, par le nom : %v", err)
	}
	if got, err := f.projects.Get(ctx, o, tenant.AllTeams(), h.Slug); err != nil || got.Agent != nil || got.TeamID != general {
		t.Fatalf("projet de l'autre équipe après la tentative : %+v, %v", got, err)
	}
	// Archivé : même réponse (pas d'oracle sur l'état d'un projet d'une autre équipe).
	old, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "old", HostRef: "old", TeamID: general})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.projects.SetArchived(ctx, f.actor, o, old.Slug, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.enroll(t, webToken(), "old"); authKey(err) != agent.KeyHostTaken {
		t.Fatalf("hôte archivé d'une autre équipe, par le nom : %v", err)
	}
	// L'équipe du projet le rattache par le nom ; ensuite, Web reçoit toujours « pris ».
	own, err := f.enroll(t, f.enrollment(t, o, agent.EnrollmentInput{TeamID: general}), "db-prod")
	if err != nil || own.Created || own.Project.ID != h.ID || own.Agent.TeamID == nil || *own.Agent.TeamID != general {
		t.Fatalf("rattachement par le nom dans l'équipe : %+v, %v", own, err)
	}
	if _, err := f.enroll(t, webToken(), "db-prod"); authKey(err) != agent.KeyHostTaken {
		t.Fatalf("hôte suivi d'une autre équipe, par le nom : %v", err)
	}
	// Projet désigné, puis passé dans une autre équipe avant l'inscription.
	moved, err := f.projects.Create(ctx, f.actor, o, project.Input{Kind: project.KindHost, Name: "srv-moved", HostRef: "srv-moved", TeamID: web.ID})
	if err != nil {
		t.Fatal(err)
	}
	tok := f.enrollment(t, o, agent.EnrollmentInput{TeamID: web.ID, ProjectSlug: moved.Slug})
	if err := f.projects.SetTeam(ctx, f.actor, o, moved.Slug, general); err != nil {
		t.Fatal(err)
	}
	if _, err := f.enroll(t, tok, "srv-moved"); authKey(err) != agent.KeyProjectUnavailable {
		t.Fatalf("projet désigné passé dans une autre équipe : %v", err)
	}
}
