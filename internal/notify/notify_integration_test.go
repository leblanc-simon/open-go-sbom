//go:build integration

package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/secret"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/locales"
)

// stubLoader présente chaque violation sous un nom fixe.
type stubLoader struct{}

func (stubLoader) Items(_ context.Context, _ *db.OrgTx, ids []uuid.UUID) ([]Item, error) {
	out := make([]Item, len(ids))
	for i, id := range ids {
		out[i] = Item{ViolationID: id, Policy: "règle", Subject: "agent", Agent: "srv"}
	}
	return out, nil
}

type fixture struct {
	t    *testing.T
	pool *db.Pool
	svc  *Service
	rec  *recorder
	org  tenant.OrgID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	box, err := secret.New(map[string][]byte{"k1": []byte(strings.Repeat("k", 32))}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := locale.New(locales.FS, ".", "fr")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, pool: d.App, rec: &recorder{}}
	f.svc = NewService(Options{Pool: d.App, Secrets: box, Sender: f.rec, Loader: stubLoader{}, Catalog: cat})
	f.org = f.newOrg()
	return f
}

func (f *fixture) newOrg() tenant.OrgID {
	f.t.Helper()
	org, err := tenant.NewOrgID()
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(org, `INSERT INTO organizations (id, slug, name, default_language) VALUES ($1, $2, 'Acme', 'fr')`, org,
		"o-"+strings.ReplaceAll(org.String()[24:], "-", ""))
	return org
}

func (f *fixture) exec(org tenant.OrgID, q string, args ...any) {
	f.t.Helper()
	if err := f.pool.InOrg(context.Background(), org, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s : %v", q, err)
	}
}

func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(context.Background(), q, args...).Scan(&n)
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// violation crée une politique d'agent, un agent et une violation ouverte.
func (f *fixture) violation(channel uuid.UUID, mode Mode) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	pol, agent, v := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	f.exec(f.org, `INSERT INTO policies (org_id, id, name, subject, expression, delivery, created_at, updated_at)
		VALUES ($1, $2, $3, 'agent', 'true', $4, now(), now())`, f.org, pol, "p-"+pol.String()[24:], mode)
	f.exec(f.org, `INSERT INTO policy_channels (org_id, policy_id, channel_id) VALUES ($1, $2, $3)`, f.org, pol, channel)
	f.exec(f.org, `INSERT INTO agents (org_id, id, kind, name) VALUES ($1, $2, 'repo', $3)`, f.org, agent, "a-"+agent.String()[24:])
	f.exec(f.org, `INSERT INTO policy_violations (org_id, id, policy_id, subject, agent_id, opened_at, last_seen_at)
		VALUES ($1, $2, $3, 'agent', $4, now(), now())`, f.org, v, pol, agent)
	if err := f.pool.InOrg(context.Background(), f.org, func(tx *db.OrgTx) error {
		return Queue(context.Background(), tx, time.Now(), []Opened{{ViolationID: v, PolicyID: pol, Mode: mode}})
	}); err != nil {
		f.t.Fatal(err)
	}
	return v, pol
}

func TestChannelsCRUDAndIsolation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	actor := audit.Actor{Email: "admin@example.org"}
	c, err := f.svc.CreateChannel(ctx, f.org, actor, Input{Name: "Ops", Kind: KindEmail, Enabled: true,
		Settings: Settings{Recipients: []string{"ops@example.org"}}})
	if err != nil || c.HasSecret || c.Settings.Recipients[0] != "ops@example.org" {
		t.Fatalf("%+v : %v", c, err)
	}
	if _, err := f.svc.CreateChannel(ctx, f.org, actor, Input{Name: "ops", Kind: KindEmail,
		Settings: Settings{Recipients: []string{"x@example.org"}}}); err == nil {
		t.Fatal("nom en double accepté")
	} else if v, ok := account.IsValidation(err); !ok || v.Key != KeyNameTaken {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateChannel(ctx, f.org, actor, c.ID, Input{Name: "Ops", Kind: KindSlack, Secret: "https://hooks.slack.com/x"}); err == nil {
		t.Fatal("changement de nature accepté")
	}
	hook, err := f.svc.CreateChannel(ctx, f.org, actor, Input{Name: "Hook", Kind: KindWebhook, Enabled: true,
		Settings: Settings{URL: "https://hooks.example.org/x"}, Secret: "0123456789abcdef"})
	if err != nil || !hook.HasSecret {
		t.Fatal(err)
	}
	other := f.newOrg()
	if _, err := f.svc.Channel(ctx, other, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canal d'une autre organisation : %v", err)
	}
	if err := f.svc.DeleteChannel(ctx, other, actor, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.svc.TestChannel(ctx, other, actor, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if cs, _ := f.svc.Channels(ctx, other); len(cs) != 0 {
		t.Fatal("canaux d'une autre organisation visibles")
	}
	// Canal inactif : les envois attendent ; le réactiver les remet en file.
	f.violation(hook.ID, ModeImmediate)
	if _, err := f.svc.UpdateChannel(ctx, f.org, actor, hook.ID, Input{Name: "Hook", Kind: KindWebhook, Enabled: false,
		Settings: Settings{URL: "https://hooks.example.org/x"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.InTx(ctx, func(tx *db.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM jobs`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Send(ctx, f.org, hook.ID, ModeImmediate); err != nil || len(f.rec.requests) != 0 {
		t.Fatalf("envoi sur un canal inactif : %v", err)
	}
	if _, err := f.svc.UpdateChannel(ctx, f.org, actor, hook.ID, Input{Name: "Hook", Kind: KindWebhook, Enabled: true,
		Settings: Settings{URL: "https://hooks.example.org/y"}, Secret: "0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := f.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE kind = $1 AND status = 'pending'`, SendKind).Scan(&pending)
	}); err != nil || pending != 1 {
		t.Fatalf("envoi non remis en file à la réactivation : %d, %v", pending, err)
	}
	if err := f.svc.Send(ctx, f.org, hook.ID, ModeImmediate); err != nil || len(f.rec.requests) != 1 ||
		f.rec.requests[0].URL != "https://hooks.example.org/y" {
		t.Fatalf("envoi : %v %+v", err, f.rec.requests)
	}
	if err := f.svc.DeleteChannel(ctx, f.org, actor, hook.ID); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM notification_deliveries`) != 0 {
		t.Fatal("envois gardés après suppression du canal")
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action LIKE 'channel.%'`); n != 5 {
		t.Fatalf("audit : %d", n)
	}
}

func TestQueueDigestAndRetries(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	actor := audit.Actor{}
	c, err := f.svc.CreateChannel(ctx, f.org, actor, Input{Name: "Ops", Kind: KindEmail, Enabled: true,
		Settings: Settings{Recipients: []string{"ops@example.org"}}})
	if err != nil {
		t.Fatal(err)
	}
	v, pol := f.violation(c.ID, ModeDigest)
	// Une seconde mise en file du même couple ne crée rien.
	if err := f.pool.InOrg(ctx, f.org, func(tx *db.OrgTx) error {
		return Queue(ctx, tx, time.Now(), []Opened{{ViolationID: v, PolicyID: pol, Mode: ModeDigest}})
	}); err != nil {
		t.Fatal(err)
	}
	if f.count(`SELECT count(*) FROM notification_deliveries`) != 1 {
		t.Fatal("envoi en double")
	}
	if err := f.svc.DigestOrgHandler().Handle(ctx, jobs.Execution{OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	f.rec.err = &SendError{Key: KeySendSMTP}
	if err := f.svc.SendHandler().Handle(ctx, jobs.Execution{OrgID: f.org,
		Payload: []byte(`{"channel_id":"` + c.ID.String() + `","mode":"digest"}`)}); err == nil {
		t.Fatal("échec non remonté")
	}
	f.rec.err = nil
	if err := f.svc.Send(ctx, f.org, c.ID, ModeDigest); err != nil {
		t.Fatal(err)
	}
	if len(f.rec.mails) != 2 || f.rec.mails[0].MessageID != f.rec.mails[1].MessageID ||
		!strings.Contains(f.rec.mails[1].Subject, "résumé quotidien") {
		t.Fatalf("courriels %+v", f.rec.mails)
	}
	if f.count(`SELECT count(*) FROM notification_deliveries WHERE state = 'sent'`) != 1 {
		t.Fatal("envoi non marqué")
	}
	ch, _ := f.svc.Channel(ctx, f.org, c.ID)
	if ch.LastSuccessAt == nil || ch.LastFailureAt == nil || ch.LastErrorKey != KeySendSMTP || ch.Policies != 1 {
		t.Fatalf("état du canal %+v", ch)
	}
	if err := f.svc.SendHandler().Handle(ctx, jobs.Execution{OrgID: f.org, Payload: []byte(`{"channel_id":"` + c.ID.String() + `","mode":"x"}`)}); !jobs.IsPermanent(err) {
		t.Fatalf("mode inconnu : %v", err)
	}
	if s := f.svc.DigestSchedule(); s.Name != DigestAllKind || s.Every != 24*time.Hour {
		t.Fatalf("échéance %+v", s)
	}
	if err := f.svc.DigestAllHandler().Handle(ctx, jobs.Execution{}); err != nil {
		t.Fatal(err)
	}
	// Essai : succès, puis échec noté et journalisé.
	if sendErr, err := f.svc.TestChannel(ctx, f.org, actor, c.ID); sendErr != nil || err != nil {
		t.Fatalf("essai : %v, %v", sendErr, err)
	}
	f.rec.err = &SendError{Key: KeySendUnconfigured}
	if sendErr, err := f.svc.TestChannel(ctx, f.org, actor, c.ID); ErrorKey(sendErr) != KeySendUnconfigured || err != nil {
		t.Fatalf("essai en échec : %v, %v", sendErr, err)
	}
	f.rec.err = nil
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'channel.tested' AND details->>'outcome' = $1`, KeySendUnconfigured); n != 1 {
		t.Fatalf("audit de l'essai : %d", n)
	}
	// Rotation : rien à faire avec la seule clé active.
	if n, err := f.svc.RotateSecrets(ctx); err != nil || n != 0 {
		t.Fatalf("rotation : %d, %v", n, err)
	}
}

// TestChannelSecretNeverFollowsNewDestination : SEC2-04. Changer le serveur Matrix ou l'URL
// du webhook générique d'un canal exige de ressaisir le secret : un administrateur qui ne
// le connaît pas ne le fait pas envoyer (jeton Matrix) ni signer des messages (clé HMAC)
// vers l'adresse de son choix. Les autres réglages se modifient sans le secret.
func TestChannelSecretNeverFollowsNewDestination(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a1 := audit.Actor{Email: "admin1@example.org"}
	a2 := audit.Actor{Email: "admin2@example.org"}
	matrix := Input{Name: "Salon", Kind: KindMatrix, Enabled: true,
		Settings: Settings{Homeserver: "https://matrix.example.org", Room: "!abc:example.org"}, Secret: "syt_SECRET_BOT_TOKEN"}
	c, err := f.svc.CreateChannel(ctx, f.org, a1, matrix)
	if err != nil {
		t.Fatal(err)
	}
	moved := matrix
	moved.Secret, moved.Settings.Homeserver = "", "https://attacker.example.net"
	if _, err := f.svc.UpdateChannel(ctx, f.org, a2, c.ID, moved); err == nil {
		t.Fatal("serveur Matrix changé sans ressaisir le jeton")
	} else if v, ok := account.IsValidation(err); !ok || v.Key != KeySecretRequired || v.Field != "secret" {
		t.Fatal(err)
	}
	if _, err := f.svc.TestChannel(ctx, f.org, a2, c.ID); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.rec.requests {
		if strings.Contains(r.URL, "attacker.example.net") {
			t.Fatalf("jeton envoyé au nouveau serveur : %s %s", r.Method, r.URL)
		}
	}
	// Autre salon, même serveur : le jeton est gardé.
	room := matrix
	room.Secret, room.Settings.Room = "", "!def:example.org"
	if _, err := f.svc.UpdateChannel(ctx, f.org, a2, c.ID, room); err != nil {
		t.Fatalf("changement de salon sans le jeton : %v", err)
	}
	// Nouveau serveur avec le jeton ressaisi : accepté, journalisé.
	moved.Secret = "syt_OTHER_TOKEN"
	if _, err := f.svc.UpdateChannel(ctx, f.org, a2, c.ID, moved); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'channel.updated' AND details->>'destination' = 'changed'`); n != 1 {
		t.Fatalf("changements de destination journalisés : %d", n)
	}
	// Webhook générique : la clé HMAC ne suit pas une nouvelle URL.
	hook, err := f.svc.CreateChannel(ctx, f.org, a1, Input{Name: "Hook", Kind: KindWebhook, Enabled: true,
		Settings: Settings{URL: "https://hooks.example.org/x"}, Secret: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateChannel(ctx, f.org, a2, hook.ID, Input{Name: "Hook", Kind: KindWebhook, Enabled: true,
		Settings: Settings{URL: "https://attacker.example.net/hook"}}); err == nil {
		t.Fatal("URL du webhook changée sans ressaisir la clé")
	}
}
