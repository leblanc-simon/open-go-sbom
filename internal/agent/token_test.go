package agent

import (
	"testing"

	"leblanc.io/lotor/internal/token"
)

// TestKindOfAcceptsOnlyAgentTokens : un jeton personnel n'ouvre jamais l'API des agents,
// même bien formé.
func TestKindOfAcceptsOnlyAgentTokens(t *testing.T) {
	for _, kind := range []token.Kind{KindAgent, KindEnrollment} {
		tok, err := NewToken(kind)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := KindOf(tok.Plaintext); !ok || got != kind {
			t.Fatalf("KindOf(%s) : %q %v", kind, got, ok)
		}
		if pub, _, err := ParseToken(kind, tok.Plaintext); err != nil || pub != tok.PublicID {
			t.Fatalf("relecture : %v", err)
		}
		if DisplayPrefix(kind, tok.PublicID) != "lotor_"+string(kind)+"_"+tok.PublicID[:6] {
			t.Fatal("préfixe affiché")
		}
	}
	pat, err := token.New(token.Personal)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := KindOf(pat.Plaintext); ok {
		t.Fatal("jeton personnel reconnu par l'API des agents")
	}
}
