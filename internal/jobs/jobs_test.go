package jobs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"leblanc.io/lotor/internal/tenant"
)

// Règle : délai = min(base × 2^(n−1), max) × (1 + gigue × u).
func TestBackoffDelayFollowsFormula(t *testing.T) {
	b := Backoff{Base: 10 * time.Second, Max: 30 * time.Minute, Jitter: 0.2}
	cases := []struct {
		attempt int
		u       float64
		want    time.Duration
	}{
		{1, 0, 10 * time.Second},
		{2, 0, 20 * time.Second},
		{3, 0, 40 * time.Second},
		{8, 0, 1280 * time.Second},
		{9, 0, 30 * time.Minute}, // 2 560 s plafonné
		{50, 0, 30 * time.Minute},
		{1, 0.5, 11 * time.Second},
		{9, 0.999999, 30*time.Minute + time.Duration(float64(6*time.Minute)*0.999999)},
	}
	for _, c := range cases {
		if got := b.Delay(c.attempt, c.u); got != c.want {
			t.Errorf("Delay(%d, %v) = %s, attendu %s", c.attempt, c.u, got, c.want)
		}
	}
	if got := (Backoff{Base: time.Second, Max: time.Second}).Delay(3, 0.9); got != time.Second {
		t.Errorf("sans gigue : %s", got)
	}
}

func TestScheduleGrid(t *testing.T) {
	daily := Schedule{Name: "x", Every: 24 * time.Hour, Offset: 3 * time.Hour}
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct{ now, last, next string }{
		{"2026-10-31T10:00:00Z", "2026-10-31T03:00:00Z", "2026-11-01T03:00:00Z"},
		{"2026-10-31T02:59:59Z", "2026-10-30T03:00:00Z", "2026-10-31T03:00:00Z"},
		{"2026-10-31T03:00:00Z", "2026-10-31T03:00:00Z", "2026-11-01T03:00:00Z"},
		{"2026-10-31T12:00:00+02:00", "2026-10-31T03:00:00Z", "2026-11-01T03:00:00Z"},
		{"1969-12-31T01:00:00Z", "1969-12-30T03:00:00Z", "1969-12-31T03:00:00Z"},
	}
	for _, c := range cases {
		if got := daily.lastPoint(at(c.now)); !got.Equal(at(c.last)) {
			t.Errorf("lastPoint(%s) = %s, attendu %s", c.now, got, c.last)
		}
		if got := daily.nextPoint(at(c.now)); !got.Equal(at(c.next)) {
			t.Errorf("nextPoint(%s) = %s, attendu %s", c.now, got, c.next)
		}
	}
}

func TestScheduleValidate(t *testing.T) {
	ok := Schedule{Name: "vulndb.check", Every: time.Hour, Job: Job{Kind: "vulndb.check"}}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Schedule){
		"nom":              func(s *Schedule) { s.Name = "Bad Name" },
		"période courte":   func(s *Schedule) { s.Every = time.Millisecond },
		"décalage négatif": func(s *Schedule) { s.Offset = -time.Second },
		"décalage ≥ période": func(s *Schedule) {
			s.Offset = time.Hour
		},
		"job invalide": func(s *Schedule) { s.Job.Kind = "" },
	} {
		s := ok
		edit(&s)
		if err := s.validate(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestJobValidate(t *testing.T) {
	if p, err := (Job{Kind: "ingest.decode"}).validate(); err != nil || string(p) != "{}" {
		t.Fatalf("job minimal : %s, %v", p, err)
	}
	if p, err := (Job{Kind: "a", Payload: map[string]int{"n": 1}}).validate(); err != nil || string(p) != `{"n":1}` {
		t.Fatalf("charge : %s, %v", p, err)
	}
	for name, j := range map[string]Job{
		"type vide":          {},
		"type majuscule":     {Kind: "Ingest.decode"},
		"type point final":   {Kind: "ingest."},
		"type trop long":     {Kind: strings.Repeat("a", 65)},
		"priorité haute":     {Kind: "a", Priority: MaxPriority + 1},
		"priorité basse":     {Kind: "a", Priority: MinPriority - 1},
		"tentatives":         {Kind: "a", MaxAttempts: MaxAttemptsLimit + 1},
		"tentatives < 0":     {Kind: "a", MaxAttempts: -1},
		"clé trop longue":    {Kind: "a", UniqueKey: strings.Repeat("k", 201)},
		"charge invalide":    {Kind: "a", Payload: make(chan int)},
		"charge trop grosse": {Kind: "a", Payload: strings.Repeat("x", MaxPayloadSize)},
	} {
		if _, err := j.validate(); !errors.Is(err, ErrInvalidJob) {
			t.Errorf("%s : err = %v", name, err)
		}
	}
}

func TestErrorTextIsBoundedAndValidUTF8(t *testing.T) {
	short := errors.New("court")
	if got := errorText(short); got != "court" {
		t.Fatal(got)
	}
	long := errors.New(strings.Repeat("é", maxErrorLen))
	got := errorText(long)
	if len(got) > maxErrorLen+len("…") || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("troncature : %d octets, valide %v", len(got), utf8.ValidString(got))
	}
	if got := errorText(errors.New("a\xffb")); !utf8.ValidString(got) {
		t.Fatalf("UTF-8 invalide conservé : %q", got)
	}
}

func TestPermanentAndDecode(t *testing.T) {
	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) non nil")
	}
	base := errors.New("cause")
	p := Permanent(base)
	if !IsPermanent(p) || !errors.Is(p, base) || p.Error() != "cause" || IsPermanent(base) {
		t.Fatal("Permanent ne marque pas l'erreur")
	}
	var v struct{ Ref string }
	e := Execution{Kind: "x", Payload: []byte(`{"Ref":"r"}`)}
	if err := e.Decode(&v); err != nil || v.Ref != "r" {
		t.Fatalf("Decode : %v", err)
	}
	e.Payload = []byte(`{"Other":1}`)
	if err := e.Decode(&v); !IsPermanent(err) {
		t.Fatalf("champ inconnu : %v", err)
	}
}

func TestRunnerOptions(t *testing.T) {
	o := RunnerOptions{}.withDefaults()
	if o.Concurrency != DefaultConcurrency || o.Lease != DefaultLease || o.Backoff.Base != DefaultRetryBase ||
		o.WorkerID == "" || o.Clock == nil || o.Rand == nil || o.Logger == nil || o.validate() != nil {
		t.Fatalf("défauts : %+v", o)
	}
	for name, edit := range map[string]func(*RunnerOptions){
		"workers":  func(o *RunnerOptions) { o.Concurrency = -1 },
		"bail":     func(o *RunnerOptions) { o.Lease = time.Millisecond },
		"négatif":  func(o *RunnerOptions) { o.Retention = -time.Second },
		"réessais": func(o *RunnerOptions) { o.Backoff = Backoff{Base: time.Minute, Max: time.Second} },
		"gigue":    func(o *RunnerOptions) { o.Backoff.Jitter = 2 },
	} {
		o := RunnerOptions{}.withDefaults()
		edit(&o)
		if o.validate() == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if err := NewRunner(nil, RunnerOptions{Concurrency: -1}).Start(context.Background()); err == nil {
		t.Fatal("Start avec des options invalides")
	}
}

func TestRegister(t *testing.T) {
	r := NewRunner(nil, RunnerOptions{})
	h := HandlerFunc(func(context.Context, Execution) error { return nil })
	if err := r.Register("ingest.decode", h, WithOrgLimit(2), WithTimeout(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if k := r.kinds["ingest.decode"]; k.orgLimit != 2 || k.timeout != time.Minute {
		t.Fatalf("options non appliquées : %+v", k)
	}
	for name, err := range map[string]error{
		"doublon":         r.Register("ingest.decode", h),
		"type invalide":   r.Register("Bad", h),
		"handler nil":     r.Register("a.b", nil),
		"plafond négatif": r.Register("a.c", h, WithOrgLimit(-1)),
	} {
		if err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestCallRecoversPanic(t *testing.T) {
	err := call(context.Background(), HandlerFunc(func(context.Context, Execution) error { panic("boum") }), Execution{Kind: "k"})
	if err == nil || !strings.Contains(err.Error(), "panique dans le handler de k : boum") {
		t.Fatalf("err = %v", err)
	}
}

func TestClock(t *testing.T) {
	fixed := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	if got := ClockFunc(func() time.Time { return fixed }).Now(); !got.Equal(fixed) {
		t.Fatal(got)
	}
	if d := time.Since(SystemClock().Now()); d < 0 || d > time.Second {
		t.Fatalf("horloge du système décalée de %s", d)
	}
}

func TestNullHelpers(t *testing.T) {
	if nullOrg(tenant.OrgID{}) != nil || nullString("") != nil || nullString("a") != "a" {
		t.Fatal("valeurs NULL")
	}
}
