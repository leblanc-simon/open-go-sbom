package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNewOrgIDIsVersion7(t *testing.T) {
	org, err := NewOrgID()
	if err != nil {
		t.Fatal(err)
	}
	if org.IsZero() || org.UUID().Version() != 7 {
		t.Fatalf("NewOrgID = %v (version %d)", org, org.UUID().Version())
	}
}

func TestParseOrgID(t *testing.T) {
	want := uuid.MustParse("0192e1a4-7b6c-7d2e-9f00-112233445566")
	got, err := ParseOrgID(want.String())
	if err != nil || got.UUID() != want || got.String() != want.String() {
		t.Fatalf("ParseOrgID = %v, %v", got, err)
	}
	if _, err := ParseOrgID("pas-un-uuid"); err == nil {
		t.Fatal("un identifiant invalide est accepté")
	}
	if _, err := ParseOrgID(uuid.Nil.String()); !errors.Is(err, ErrZeroOrgID) {
		t.Fatalf("UUID nul : err = %v, attendu ErrZeroOrgID", err)
	}
}

func TestValueRefusesZero(t *testing.T) {
	if _, err := (OrgID{}).Value(); !errors.Is(err, ErrZeroOrgID) {
		t.Fatalf("Value() d'un zéro : err = %v", err)
	}
	org, _ := NewOrgID()
	v, err := org.Value()
	if err != nil || v != org.String() {
		t.Fatalf("Value() = %v, %v", v, err)
	}
}

func TestScan(t *testing.T) {
	org, _ := NewOrgID()
	for _, src := range []any{org.String(), []byte(org.String())} {
		var got OrgID
		if err := got.Scan(src); err != nil || got != org {
			t.Fatalf("Scan(%T) = %v, %v", src, got, err)
		}
	}
	var got OrgID
	if err := got.Scan(nil); err == nil {
		t.Fatal("Scan(nil) accepté")
	}
	if err := got.Scan(uuid.Nil.String()); !errors.Is(err, ErrZeroOrgID) {
		t.Fatalf("Scan(zéro) : err = %v", err)
	}
	if err := got.Scan("xyz"); err == nil {
		t.Fatal("Scan d'un texte invalide accepté")
	}
}

func TestContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("organisation trouvée dans un contexte vide")
	}
	if _, ok := FromContext(NewContext(context.Background(), OrgID{})); ok {
		t.Fatal("organisation zéro considérée comme présente")
	}
	org, _ := NewOrgID()
	got, ok := FromContext(NewContext(context.Background(), org))
	if !ok || got != org {
		t.Fatalf("FromContext = %v, %v", got, ok)
	}
}
