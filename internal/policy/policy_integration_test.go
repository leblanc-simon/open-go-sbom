//go:build integration

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/delivery"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/vuln"
)

// TestKEVProductionOnHandBuiltSet : le modèle « KEV sur un projet de production »
// déclenche sur le dépôt étiqueté env=production qui embarque log4shell, et pas sur un
// dépôt de pré-production au même inventaire.
func TestKEVProductionOnHandBuiltSet(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	staging, stagingMain := newID(), newID()
	e.exec(e.org, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id, team_id, labels)
		VALUES ($1, $2, 'repo', 'web', 'web', $3, $1, '{"env": "staging"}')`, e.org, staging, e.agent)
	e.exec(e.org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', 'main')`,
		e.org, stagingMain, staging)
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	e.push(e.org, e.agent, staging, testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	e.analyze(e.org, stagingMain)
	if e.jobs(ProjectKind) != 2 {
		t.Fatalf("évaluations en file après analyse : %d", e.jobs(ProjectKind))
	}
	p := e.fromTemplate(e.org, TemplateKEVProduction)
	e.evaluate(e.org, e.repo)
	e.evaluate(e.org, staging)
	if e.open(e.org, p.ID) != 1 {
		t.Fatalf("violations ouvertes : %d", e.open(e.org, p.ID))
	}
	if n := e.count(e.org, `SELECT count(*) FROM policy_violations WHERE project_id = $1`, staging); n != 0 {
		t.Fatalf("pré-production en violation : %d", n)
	}
	page, err := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, "", 10)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("liste %+v : %v", page, err)
	}
	v := page.Items[0]
	if v.Policy != TemplateKEVProduction || v.VulnID != "CVE-2021-44228" || v.Component != log4j || v.Project != "api" || !v.KEV || v.Ref != "main" {
		t.Fatalf("violation %+v", v)
	}
	// Réévaluer ne rouvre rien ; un constat déclaré non affecté résout la violation.
	e.evaluate(e.org, e.repo)
	if n := e.count(e.org, `SELECT count(*) FROM policy_violations`); n != 1 {
		t.Fatalf("violations après réévaluation : %d", n)
	}
	e.exec(e.org, `INSERT INTO triage_decisions (org_id, id, scope, vuln_id, purl_base, action, status, comment, author_label, created_at)
		VALUES ($1, $2, 'org', 'CVE-2021-44228', 'pkg:maven/org.apache.logging.log4j/log4j-core', 'set', 'not_affected', 'non utilisé', 'test', now())`,
		e.org, newID())
	e.exec(e.org, `UPDATE findings SET triage_status = 'not_affected', triage_decision_id = (SELECT id FROM triage_decisions LIMIT 1)`)
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 0 {
		t.Fatal("violation non résolue après le triage")
	}
	// Une nouvelle violation n'est ouverte qu'après la résolution de la précédente.
	e.exec(e.org, `UPDATE findings SET triage_status = 'in_triage', triage_decision_id = NULL`)
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 1 || e.count(e.org, `SELECT count(*) FROM policy_violations`) != 2 {
		t.Fatal("violation non rouverte")
	}
}

// TestCriticalFixOnHandBuiltSet : correctif connu depuis 31 jours, et pas 29.
func TestCriticalFixOnHandBuiltSet(t *testing.T) {
	e := newEnv(t)
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	p := e.fromTemplate(e.org, TemplateCriticalFix)
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 0 {
		t.Fatal("correctif récent : violation ouverte à tort")
	}
	e.exec(e.org, `UPDATE findings SET fixed_seen_at = $1, first_seen_at = $1`, e.clock.Add(-29*24*time.Hour))
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 0 {
		t.Fatal("29 jours : violation ouverte à tort")
	}
	e.exec(e.org, `UPDATE findings SET fixed_seen_at = $1, first_seen_at = $1`, e.clock.Add(-31*24*time.Hour))
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 1 {
		t.Fatal("31 jours : violation absente")
	}
	// Sans correctif (base qui le retire), fixed_seen_at est effacé par l'analyse.
	e.publish(vuln.FixNotFixed)
	e.analyze(e.org, e.main)
	if n := e.count(e.org, `SELECT count(*) FROM findings WHERE fixed_seen_at IS NOT NULL`); n != 0 {
		t.Fatalf("fixed_seen_at gardé sans correctif : %d", n)
	}
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 0 {
		t.Fatal("violation gardée sans correctif")
	}
}

// TestAgentSilentOnHandBuiltSet : un agent dépôt muet depuis 10 jours viole la règle, un
// agent vu hier non.
func TestAgentSilentOnHandBuiltSet(t *testing.T) {
	e := newEnv(t)
	quiet, recent := newID(), newID()
	e.exec(e.org, `INSERT INTO agents (org_id, id, kind, name, created_at, last_seen_at) VALUES
		($1, $2, 'repo', 'muet', $4, $4), ($1, $3, 'repo', 'vivant', $4, $5)`, e.org, quiet, recent,
		e.clock.Add(-10*24*time.Hour), e.clock.Add(-24*time.Hour))
	e.exec(e.org, `UPDATE agents SET last_seen_at = $2 WHERE id = $1`, e.agent, e.clock)
	p := e.fromTemplate(e.org, TemplateAgentSilent)
	if err := e.policies.EvaluateOrg(context.Background(), e.org); err != nil {
		t.Fatal(err)
	}
	if e.open(e.org, p.ID) != 1 || e.count(e.org, `SELECT count(*) FROM policy_violations WHERE agent_id = $1`, quiet) != 1 {
		t.Fatal("agent muet non détecté, ou agent actif signalé")
	}
	// L'évaluation de l'organisation met aussi en file celle de chaque projet.
	if e.jobs(ProjectKind) == 0 {
		t.Fatal("projets non mis en évaluation")
	}
	e.exec(e.org, `UPDATE agents SET last_seen_at = $2 WHERE id = $1`, quiet, e.clock)
	if err := e.policies.EvaluateAgents(context.Background(), e.org); err != nil {
		t.Fatal(err)
	}
	if e.open(e.org, p.ID) != 0 {
		t.Fatal("violation de l'agent revenu non résolue")
	}
	matches, _, err := e.policies.Preview(context.Background(), e.org, SubjectAgent, `agent.name == "muet"`)
	if err != nil || matches != 1 {
		t.Fatalf("aperçu %d : %v", matches, err)
	}
}

// TestChannelDownGetsMessagesWithoutDuplicate : un canal en panne reçoit ses messages
// après rétablissement (réessais du job), une seule fois, signés.
func TestChannelDownGetsMessagesWithoutDuplicate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := newReceiver(t, 3)
	ch := e.webhook(e.org, r, "0123456789abcdef-secret")
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	p := e.fromTemplate(e.org, TemplateKEVProduction, ch.ID)
	e.evaluate(e.org, e.repo)
	if e.jobs(notify.SendKind) != 1 || e.count(e.org, `SELECT count(*) FROM notification_deliveries WHERE state = 'pending'`) != 1 {
		t.Fatal("envoi immédiat non mis en file")
	}
	// Trois tentatives en échec (le job serait réessayé), puis le canal revient.
	for i := range 3 {
		if err := e.notifier.Send(ctx, e.org, ch.ID, notify.ModeImmediate); err == nil {
			t.Fatalf("tentative %d : succès inattendu", i)
		}
	}
	c, _ := e.notifier.Channel(ctx, e.org, ch.ID)
	if c.LastErrorKey != notify.KeySendStatus || c.LastFailureAt == nil {
		t.Fatalf("échec non noté : %+v", c)
	}
	if err := e.notifier.Send(ctx, e.org, ch.ID, notify.ModeImmediate); err != nil {
		t.Fatal(err)
	}
	// Une évaluation, une tentative et un passage quotidien de plus n'envoient rien.
	e.evaluate(e.org, e.repo)
	if err := e.notifier.Send(ctx, e.org, ch.ID, notify.ModeImmediate); err != nil {
		t.Fatal(err)
	}
	attempts, accepted, deliveries := r.snapshot()
	if attempts != 4 || len(accepted) != 1 {
		t.Fatalf("%d tentatives, %d messages acceptés", attempts, len(accepted))
	}
	for _, d := range deliveries {
		if d != deliveries[0] {
			t.Fatalf("identifiant de message changé d'une tentative à l'autre : %v", deliveries)
		}
	}
	var body struct {
		Type       string `json:"type"`
		Violations []struct {
			Policy struct {
				Name     string `json:"name"`
				Blocking bool   `json:"blocking"`
			} `json:"policy"`
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
		} `json:"violations"`
	}
	if err := json.Unmarshal([]byte(accepted[0]), &body); err != nil {
		t.Fatal(err)
	}
	if body.Type != "violations.opened" || len(body.Violations) != 1 || body.Violations[0].Vulnerability.ID != "CVE-2021-44228" ||
		!body.Violations[0].Policy.Blocking || body.Violations[0].Policy.Name != p.Name {
		t.Fatalf("message %s", accepted[0])
	}
	r.mu.Lock()
	h := r.accepted[0]
	r.mu.Unlock()
	var ts int64
	if _, err := fmtSscan(h.Get(notify.HeaderTimestamp), &ts); err != nil {
		t.Fatal(err)
	}
	if h.Get(notify.HeaderSignature) != "sha256="+notify.Sign([]byte("0123456789abcdef-secret"), ts, []byte(accepted[0])) {
		t.Fatal("signature invalide")
	}
	if e.count(e.org, `SELECT count(*) FROM notification_deliveries WHERE state = 'sent'`) != 1 {
		t.Fatal("envoi non marqué")
	}
}

// TestDigestAndSkippedDeliveries : les violations d'une règle « résumé » attendent le
// passage quotidien ; une violation résolue avant l'envoi n'est pas envoyée.
func TestDigestAndSkippedDeliveries(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := newReceiver(t, 0)
	ch := e.webhook(e.org, r, "0123456789abcdef")
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	e.exec(e.org, `UPDATE findings SET fixed_seen_at = $1`, e.clock.Add(-40*24*time.Hour))
	e.fromTemplate(e.org, TemplateCriticalFix, ch.ID)
	e.evaluate(e.org, e.repo)
	if e.jobs(notify.SendKind) != 0 || e.count(e.org, `SELECT count(*) FROM notification_deliveries WHERE mode = 'digest'`) != 1 {
		t.Fatal("un résumé ne part pas tout de suite")
	}
	if err := e.notifier.DigestOrgHandler().Handle(ctx, jobsExecution(e.org)); err != nil {
		t.Fatal(err)
	}
	if e.jobs(notify.SendKind) != 1 {
		t.Fatal("résumé non mis en file")
	}
	if err := e.notifier.Send(ctx, e.org, ch.ID, notify.ModeDigest); err != nil {
		t.Fatal(err)
	}
	_, accepted, _ := r.snapshot()
	if len(accepted) != 1 || !strings.Contains(accepted[0], `"type":"violations.digest"`) {
		t.Fatalf("résumé %v", accepted)
	}
	// Violation résolue avant l'envoi : écartée.
	e.exec(e.org, `UPDATE findings SET triage_status = 'in_triage', fixed_seen_at = $1`, e.clock)
	e.evaluate(e.org, e.repo)
	e.exec(e.org, `UPDATE findings SET fixed_seen_at = $1`, e.clock.Add(-40*24*time.Hour))
	e.evaluate(e.org, e.repo)
	e.exec(e.org, `UPDATE findings SET fixed_seen_at = $1`, e.clock)
	e.evaluate(e.org, e.repo)
	if err := e.notifier.Send(ctx, e.org, ch.ID, notify.ModeDigest); err != nil {
		t.Fatal(err)
	}
	if _, accepted, _ = r.snapshot(); len(accepted) != 1 {
		t.Fatalf("violation résolue envoyée : %d messages", len(accepted))
	}
	if e.count(e.org, `SELECT count(*) FROM notification_deliveries WHERE state = 'skipped'`) != 1 {
		t.Fatal("envoi écarté non marqué")
	}
}

// TestVerdict : en attente avant l'analyse et l'évaluation, non conforme avec une
// violation bloquante, conforme sinon ; un instantané d'un autre agent est introuvable.
func TestVerdict(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(vuln.FixFixed)
	snap := e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	v, err := e.policies.Verdict(ctx, e.org, e.agent, snap)
	if err != nil || v.State != VerdictPending {
		t.Fatalf("avant analyse : %+v, %v", v, err)
	}
	e.analyze(e.org, e.main)
	if v, _ = e.policies.Verdict(ctx, e.org, e.agent, snap); v.State != VerdictPending {
		t.Fatalf("avant évaluation : %+v", v)
	}
	p := e.fromTemplate(e.org, TemplateKEVProduction)
	e.evaluate(e.org, e.repo)
	v, err = e.policies.Verdict(ctx, e.org, e.agent, snap)
	if err != nil || v.State != VerdictFail || v.Blocking != 1 || len(v.Policies) != 1 || v.Policies[0] != p.Name ||
		v.Language != "en" || !strings.HasPrefix(v.URL, "https://sbom.example.org/o/") {
		t.Fatalf("non conforme attendu : %+v, %v", v, err)
	}
	in := Input{Name: p.Name, Subject: p.Subject, Expression: p.Expression, Enabled: true, Blocking: false, Delivery: DeliveryNone}
	if _, err := e.policies.Update(ctx, e.org, actor, p.ID, in); err != nil {
		t.Fatal(err)
	}
	e.evaluate(e.org, e.repo)
	if v, _ = e.policies.Verdict(ctx, e.org, e.agent, snap); v.State != VerdictPass || v.Warnings != 1 {
		t.Fatalf("conforme avec avertissement attendu : %+v", v)
	}
	// Nouveau commit au même inventaire : l'ensemble est déjà analysé et évalué.
	snap2 := e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	if v, _ = e.policies.Verdict(ctx, e.org, e.agent, snap2); v.State != VerdictPass {
		t.Fatalf("commit au même inventaire : %+v", v)
	}
	if _, err := e.policies.Verdict(ctx, e.org, newID(), snap); !errors.Is(err, ErrNotFound) {
		t.Fatalf("autre agent : %v", err)
	}
	other, otherAgent, _, _ := e.newOrg("b", `{}`)
	if _, err := e.policies.Verdict(ctx, other, otherAgent, snap); !errors.Is(err, ErrNotFound) {
		t.Fatalf("autre organisation : %v", err)
	}
}

// TestPolicyLifecycleAndIsolation : validation, audit, désactivation qui résout, suppression
// qui emporte les violations, et rien de visible d'une autre organisation.
func TestPolicyLifecycleAndIsolation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)

	_, err := e.policies.Create(ctx, e.org, actor, Input{Name: "x", Subject: SubjectFinding, Expression: "finding.sevrity == 1",
		Enabled: true, Delivery: DeliveryNone})
	if ee, ok := IsExprError(err); !ok || ee.Key != KeyExprUnknownField || ee.Line != 1 {
		t.Fatalf("règle invalide : %v", err)
	}
	p := e.fromTemplate(e.org, TemplateKEVProduction)
	if e.jobs(OrgKind) != 1 {
		t.Fatal("évaluation de l'organisation non mise en file à la création")
	}
	if _, err := e.policies.Create(ctx, e.org, actor, Input{Name: strings.ToUpper(p.Name), Subject: SubjectFinding,
		Expression: "true", Delivery: DeliveryNone}); err == nil {
		t.Fatal("nom en double accepté")
	} else if v, ok := account.IsValidation(err); !ok || v.Key != KeyNameTaken {
		t.Fatalf("nom en double : %v", err)
	}
	if _, err := e.policies.Create(ctx, e.org, actor, Input{Name: "y", Subject: SubjectFinding, Expression: "true",
		Delivery: DeliveryNone, Channels: []uuid.UUID{newID()}}); err == nil {
		t.Fatal("canal inconnu accepté")
	}
	e.evaluate(e.org, e.repo)
	if e.open(e.org, p.ID) != 1 {
		t.Fatal("violation absente")
	}
	in := Input{Name: p.Name, Subject: p.Subject, Expression: p.Expression, Enabled: false, Blocking: true, Delivery: DeliveryNone}
	if _, err := e.policies.Update(ctx, e.org, actor, p.ID, in); err != nil {
		t.Fatal(err)
	}
	if e.open(e.org, p.ID) != 0 {
		t.Fatal("désactivation sans résolution")
	}

	// Isolement : l'autre organisation ne voit ni la politique ni ses violations.
	other, _, _, _ := e.newOrg("b", `{}`)
	if _, err := e.policies.Get(ctx, other, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("politique d'une autre organisation : %v", err)
	}
	if err := e.policies.Delete(ctx, other, actor, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("suppression depuis une autre organisation : %v", err)
	}
	if ps, _ := e.policies.List(ctx, other); len(ps) != 0 {
		t.Fatal("liste d'une autre organisation non vide")
	}
	if page, _ := e.policies.Violations(ctx, other, tenant.AllTeams(), Filter{Resolved: true}, "", 10); len(page.Items) != 0 {
		t.Fatal("violations d'une autre organisation visibles")
	}
	// Un membre sans équipe ne voit pas les violations des projets de l'équipe.
	if page, _ := e.policies.Violations(ctx, e.org, tenant.OnlyTeams(), Filter{Resolved: true}, "", 10); len(page.Items) != 0 {
		t.Fatal("filtre d'équipe ignoré")
	}
	if page, _ := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{Resolved: true, PolicyID: p.ID}, "", 10); len(page.Items) != 1 {
		t.Fatal("violation résolue absente")
	}

	if err := e.policies.Delete(ctx, e.org, actor, p.ID); err != nil {
		t.Fatal(err)
	}
	if e.count(e.org, `SELECT count(*) FROM policy_violations`) != 0 {
		t.Fatal("violations gardées après suppression")
	}
	if n := e.count(e.org, `SELECT count(*) FROM audit_events WHERE action IN ('policy.created', 'policy.updated', 'policy.deleted')`); n != 3 {
		t.Fatalf("audit : %d événements", n)
	}
}

// TestTriageChangeQueuesEvaluation : un changement de statut de triage met le projet en
// évaluation (point d'accroche de triage.Options.OnChange).
func TestTriageChangeQueuesEvaluation(t *testing.T) {
	e := newEnv(t)
	err := e.pool.InOrg(context.Background(), e.org, func(tx *db.OrgTx) error {
		return OnTriageChange(context.Background(), tx, []triage.Change{{ProjectID: e.repo}, {ProjectID: e.repo}})
	})
	if err != nil || e.jobs(ProjectKind) != 1 {
		t.Fatalf("%d jobs : %v", e.jobs(ProjectKind), err)
	}
}

// TestChannelSecretsAreSealed : aucun secret de canal n'est lisible en base.
func TestChannelSecretsAreSealed(t *testing.T) {
	e := newEnv(t)
	r := newReceiver(t, 0)
	const secret = "très-secret-0123456789"
	ch := e.webhook(e.org, r, secret)
	var raw []byte
	var settings string
	if err := e.pool.InOrg(context.Background(), e.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT secret, settings::text FROM notification_channels WHERE id = $1`, ch.ID).
			Scan(&raw, &settings)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(settings, secret) || len(raw) == 0 {
		t.Fatal("secret lisible en base")
	}
	if strings.Contains(e.auditText(), secret) {
		t.Fatal("secret dans le journal d'audit")
	}
	// Recopié dans une autre ligne, le chiffré ne se déchiffre plus (données associées).
	other := e.webhook(e.org, r, "0123456789abcdef")
	e.exec(e.org, `UPDATE notification_channels SET secret = $2, secret_key_id = 'k1' WHERE id = $1`, other.ID, raw)
	if err := e.notifier.Send(context.Background(), e.org, other.ID, notify.ModeImmediate); err != nil {
		t.Fatal(err) // aucun envoi en attente : rien n'est déchiffré
	}
	sendErr, err := e.notifier.TestChannel(context.Background(), e.org, actor, other.ID)
	if err != nil || notify.ErrorKey(sendErr) != notify.KeySendSecret {
		t.Fatalf("secret recopié : %v, %v", sendErr, err)
	}
	if sendErr, err := e.notifier.TestChannel(context.Background(), e.org, actor, ch.ID); sendErr != nil || err != nil {
		t.Fatalf("essai : %v, %v", sendErr, err)
	}
	if _, accepted, _ := r.snapshot(); len(accepted) != 1 || !strings.Contains(accepted[0], `"type":"test"`) {
		t.Fatalf("message de test %v", accepted)
	}
}

// auditText relit le journal d'audit en texte.
func (e *env) auditText() string {
	var out string
	if err := e.pool.InOrg(context.Background(), e.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), `SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_events`).Scan(&out)
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// TestChannelSecretsRotate : les secrets de canaux chiffrés par une ancienne clé sont
// rechiffrés avec la clé active, et restent lisibles.
func TestChannelSecretsRotate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := newReceiver(t, 0)
	ch := e.webhook(e.org, r, "0123456789abcdef")
	both, err := secret.New(map[string][]byte{"k1": []byte(strings.Repeat("k", 32)), "k2": []byte(strings.Repeat("z", 32))}, "k2")
	if err != nil {
		t.Fatal(err)
	}
	rotated := notify.NewService(notify.Options{Pool: e.pool, Secrets: both, Sender: delivery.New(delivery.Options{AllowPrivate: true}),
		Loader: e.policies, Catalog: e.catalog})
	if n, err := rotated.RotateSecrets(ctx); err != nil || n != 1 {
		t.Fatalf("rotation : %d, %v", n, err)
	}
	if n, err := rotated.RotateSecrets(ctx); err != nil || n != 0 {
		t.Fatalf("seconde rotation : %d, %v", n, err)
	}
	if e.count(e.org, `SELECT count(*) FROM notification_channels WHERE secret_key_id = 'k2'`) != 1 {
		t.Fatal("clé non changée")
	}
	if sendErr, err := rotated.TestChannel(ctx, e.org, actor, ch.ID); sendErr != nil || err != nil {
		t.Fatalf("secret illisible après rotation : %v, %v", sendErr, err)
	}
}

// TestHandlersErrorsAndPages : jobs d'évaluation, erreur d'évaluation notée sur la règle,
// projet archivé, résumé du tableau de bord et pages de violations.
func TestHandlersErrorsAndPages(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(vuln.FixFixed)
	e.push(e.org, e.agent, e.repo, testdata(t, "log4shell.cdx16.json"))
	e.analyze(e.org, e.main)
	if err := e.policies.Check(SubjectFinding, "finding.kev"); err != nil {
		t.Fatal(err)
	}
	if err := e.policies.Check("x", "true"); err == nil {
		t.Fatal("sujet inconnu accepté")
	}
	// Règle valide qui échoue sur une donnée : erreur notée, pas de violation.
	failing, err := e.policies.Create(ctx, e.org, actor, Input{Name: "équipe", Subject: SubjectFinding,
		Expression: `project.labels["team"] == "core"`, Enabled: true, Delivery: DeliveryNone})
	if err != nil {
		t.Fatal(err)
	}
	all, err := e.policies.Create(ctx, e.org, actor, Input{Name: "tout", Subject: SubjectFinding, Expression: `true`,
		Enabled: true, Blocking: true, Delivery: DeliveryNone})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.policies.ProjectHandler().Handle(ctx, jobsExecutionWith(e.org, `{"project_id":"`+e.repo.String()+`"}`)); err != nil {
		t.Fatal(err)
	}
	got, _ := e.policies.Get(ctx, e.org, failing.ID)
	if got.LastError == "" || got.LastErrorAt == nil || e.open(e.org, failing.ID) != 0 {
		t.Fatalf("erreur d'évaluation non notée : %+v", got)
	}
	if n := e.open(e.org, all.ID); n != 1 {
		t.Fatalf("violations de « tout » : %d", n)
	}
	if _, err := e.policies.Create(ctx, e.org, actor, Input{Name: "agents", Subject: SubjectAgent, Expression: `true`,
		Enabled: true, Delivery: DeliveryNone}); err != nil {
		t.Fatal(err)
	}
	if err := e.policies.EvaluateAgents(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	sum, err := e.policies.Summary(ctx, e.org, tenant.AllTeams())
	if err != nil || sum.Open != 2 || sum.Blocking != 1 || len(sum.Recent) != 2 {
		t.Fatalf("résumé %+v : %v", sum, err)
	}
	page, err := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("première page %+v : %v", page, err)
	}
	next, err := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, page.NextCursor, 1)
	if err != nil || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID {
		t.Fatalf("page suivante %+v : %v", next, err)
	}
	if _, err := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, "abc", 1); err == nil {
		t.Fatal("curseur invalide accepté")
	}
	if _, err := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, "", ViolationPageMax+1); err == nil {
		t.Fatal("page trop grande acceptée")
	}
	if m, f, err := e.policies.Preview(ctx, e.org, SubjectFinding, "finding.kev"); err != nil || m != 1 || f != 0 {
		t.Fatalf("aperçu : %d %d %v", m, f, err)
	}
	if m, f, err := e.policies.Preview(ctx, e.org, SubjectFinding, `project.labels["team"] == "x"`); err != nil || m != 0 || f != 1 {
		t.Fatalf("aperçu en échec : %d %d %v", m, f, err)
	}
	if _, _, err := e.policies.Preview(ctx, e.org, SubjectFinding, "finding.kev &&"); err == nil {
		t.Fatal("aperçu d'une règle invalide")
	}
	// Projet archivé : plus aucune violation.
	e.exec(e.org, `UPDATE projects SET archived_at = now() WHERE id = $1`, e.repo)
	if err := e.policies.OrgHandler().Handle(ctx, jobsExecution(e.org)); err != nil {
		t.Fatal(err)
	}
	e.evaluate(e.org, e.repo)
	if e.open(e.org, all.ID) != 0 {
		t.Fatal("violations d'un projet archivé gardées")
	}
	if err := e.policies.AllHandler().Handle(ctx, jobsExecution(tenant.OrgID{})); err != nil {
		t.Fatal(err)
	}
	if e.jobs(OrgKind) == 0 {
		t.Fatal("évaluation du parc non mise en file")
	}
	if err := e.policies.ProjectHandler().Handle(ctx, jobsExecutionWith(e.org, `{}`)); !jobs.IsPermanent(err) {
		t.Fatalf("charge sans projet : %v", err)
	}
	if s := Schedule(); s.Name != AllKind || s.Offset != AllOffset {
		t.Fatalf("échéance %+v", s)
	}
}

// TestContainerProjects : un conteneur (T13) hérite des étiquettes de son hôte, est évalué
// après l'analyse de sa référence, porte le verdict de son instantané, et ses violations
// quittent les listes ouvertes dès son archivage pour absence, puis sont résolues.
func TestContainerProjects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	hostAgent := newID()
	var states []project.ChildState
	if err := e.pool.InOrg(ctx, e.org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name, team_id) VALUES ($1, $2, 'host', 'srv-prod', $1)`,
			e.org, hostAgent); err != nil {
			return err
		}
		var err error
		if _, err = project.CreateHost(ctx, tx, "srv-prod", project.Labels{"env": "production"}, hostAgent, e.org.UUID()); err != nil {
			return err
		}
		states, err = project.SightContainers(ctx, tx, actor, hostAgent, []project.ContainerSighting{{Key: "shop/api",
			Context: project.ContainerContext{Engine: project.EngineDocker, Names: []string{"shop-api-1"}, Replicas: 1,
				Image: "shop/api:1.0", ImageID: "sha256:" + strings.Repeat("b", 64)}}}, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	container, ref := states[0].ProjectID, states[0].RefID
	e.publish(vuln.FixFixed)
	e.scans++
	in, err := e.ingest.Receive(ctx, e.org, hostAgent, ingest.Context{ProjectID: container, RefKind: project.RefContainer,
		RefName: "shop/api", AgentVersion: "1.0.0", ScannedAt: time.Now().Add(-time.Minute)},
		strings.NewReader(string(testdata(t, "log4shell.cdx16.json"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ingest.Decode(ctx, e.org, in.ID); err != nil {
		t.Fatal(err)
	}
	got, err := e.ingest.Get(ctx, e.org, hostAgent, in.ID)
	if err != nil || got.SnapshotID == nil {
		t.Fatalf("ingestion du conteneur %+v : %v", got, err)
	}
	e.analyze(e.org, ref)
	if e.jobs(ProjectKind) == 0 {
		t.Fatal("conteneur non mis en évaluation après son analyse")
	}
	p := e.fromTemplate(e.org, TemplateKEVProduction)
	if _, err := e.policies.Create(ctx, e.org, actor, Input{Name: "hôte", Subject: SubjectFinding,
		Expression: `project.kind == "container" && project.host == "srv-prod" && ref.kind == "container"`,
		Enabled:    true, Delivery: DeliveryNone}); err != nil {
		t.Fatal(err)
	}
	e.evaluate(e.org, container)
	if n := e.count(e.org, `SELECT count(*) FROM policy_violations WHERE project_id = $1 AND resolved_at IS NULL`, container); n != 2 {
		t.Fatalf("violations du conteneur : %d (étiquettes de l'hôte non héritées ?)", n)
	}
	if v, err := e.policies.Verdict(ctx, e.org, hostAgent, *got.SnapshotID); err != nil || v.State != VerdictFail || v.Policies[0] != p.Name {
		t.Fatalf("verdict du conteneur : %+v, %v", v, err)
	}
	// Archivé pour absence : hors des listes ouvertes tout de suite, résolu à l'évaluation.
	e.exec(e.org, `UPDATE projects SET archived_at = now(), archived_absent = true WHERE id = $1`, container)
	if sum, _ := e.policies.Summary(ctx, e.org, tenant.AllTeams()); sum.Open != 0 {
		t.Fatalf("violations d'un conteneur archivé encore ouvertes au résumé : %d", sum.Open)
	}
	if page, _ := e.policies.Violations(ctx, e.org, tenant.AllTeams(), Filter{}, "", 10); len(page.Items) != 0 {
		t.Fatal("violations d'un conteneur archivé dans la liste ouverte")
	}
	if err := e.policies.EvaluateOrg(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	e.evaluate(e.org, container)
	if n := e.count(e.org, `SELECT count(*) FROM policy_violations WHERE project_id = $1 AND resolved_at IS NULL`, container); n != 0 {
		t.Fatalf("violations du conteneur archivé non résolues : %d", n)
	}
}
