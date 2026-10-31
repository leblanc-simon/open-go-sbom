package token

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestTokenFormat(t *testing.T) {
	for _, kind := range []Kind{Agent, Enrollment, Personal} {
		tok, err := New(kind)
		if err != nil {
			t.Fatal(err)
		}
		prefix := "lotor_" + string(kind) + "_"
		if !strings.HasPrefix(tok.Plaintext, prefix) || len(tok.Plaintext) != len(prefix)+26+1+52 {
			t.Fatalf("jeton %q : préfixe ou longueur inattendus", tok.Plaintext)
		}
		if strings.ContainsAny(tok.Plaintext[len(prefix):], "-=+/") || strings.Count(tok.Plaintext, "_") != 3 {
			t.Fatalf("jeton %q : alphabet inattendu", tok.Plaintext)
		}
		if got, ok := KindOf(tok.Plaintext, Agent, Enrollment, Personal); !ok || got != kind {
			t.Fatalf("KindOf : %q %v", got, ok)
		}
		pub, hash, err := Parse(kind, tok.Plaintext)
		if err != nil || pub != tok.PublicID || hash != tok.Hash {
			t.Fatalf("relecture : %q %x %v", pub, hash, err)
		}
	}
}

// TestTokenSecretIs256BitsAndOnlyItsHashIsKept : le secret compte 256 bits, l'empreinte
// est son SHA-256, et ni l'identifiant public ni l'empreinte ne contiennent le secret.
func TestTokenSecretIs256BitsAndOnlyItsHashIsKept(t *testing.T) {
	rnd := bytes.NewReader(append(bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0xAB}, 32)...))
	tok, err := issue(Agent, rnd)
	if err != nil {
		t.Fatal(err)
	}
	secretPart := tok.Plaintext[strings.LastIndexByte(tok.Plaintext, '_')+1:]
	raw, err := b32.DecodeString(secretPart)
	if err != nil || len(raw) != 32 {
		t.Fatalf("secret de %d octets, %v", len(raw), err)
	}
	if tok.Hash != sha256.Sum256(raw) {
		t.Fatal("l'empreinte n'est pas le SHA-256 du secret")
	}
	if strings.Contains(tok.PublicID, secretPart[:10]) {
		t.Fatal("l'identifiant public contient le secret")
	}
	// Tirage épuisé : erreur, jamais un jeton partiel.
	if _, err := issue(Agent, bytes.NewReader(make([]byte, 10))); err == nil {
		t.Fatal("tirage incomplet accepté")
	}
}

func TestTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		tok, err := New(Agent)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.PublicID] || seen[tok.Plaintext] {
			t.Fatal("jeton tiré deux fois")
		}
		seen[tok.PublicID], seen[tok.Plaintext] = true, true
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	tok, err := New(Agent)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(tok.Plaintext, "lotor_agt_")
	cases := map[string]string{
		"vide":                "",
		"autre nature":        "lotor_enr_" + body,
		"préfixe étranger":    "ghp_" + body,
		"tronqué":             tok.Plaintext[:len(tok.Plaintext)-1],
		"allongé":             tok.Plaintext + "a",
		"séparateur déplacé":  "lotor_agt_" + body[:25] + "_" + body[25:26] + body[27:],
		"majuscules":          strings.ToUpper(tok.Plaintext),
		"caractère hors base": "lotor_agt_" + body[:30] + "1" + body[31:],
		"espaces":             " " + tok.Plaintext,
	}
	for name, s := range cases {
		if _, _, err := Parse(Agent, s); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s : err = %v", name, err)
		}
	}
	// Forme non canonique : le dernier caractère du secret ne porte qu'un bit utile ; en
	// changer les bits de bourrage donne le même secret sous une autre écriture.
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	last := strings.IndexByte(alphabet, body[len(body)-1])
	alt := alphabet[last&^0xF|(last+1)&0xF]
	nonCanonical := "lotor_agt_" + body[:len(body)-1] + string(alt)
	if _, _, err := Parse(Agent, nonCanonical); !errors.Is(err, ErrMalformed) {
		t.Errorf("forme non canonique acceptée : %v", err)
	}
	if _, ok := KindOf("lotor_pat_x", Agent, Enrollment); ok {
		t.Error("nature inconnue reconnue")
	}
}

func TestSecretHashMatchesInConstantTime(t *testing.T) {
	h := SecretHash(sha256.Sum256([]byte("secret")))
	if !h.Matches(h[:]) {
		t.Fatal("empreinte identique refusée")
	}
	other := sha256.Sum256([]byte("autre"))
	for name, stored := range map[string][]byte{"autre": other[:], "courte": h[:31], "vide": nil, "longue": append(h[:], 0)} {
		if h.Matches(stored) {
			t.Errorf("empreinte %s acceptée", name)
		}
	}
}

func TestDisplayPrefixHidesTheSecret(t *testing.T) {
	tok, err := New(Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if p := DisplayPrefix(Enrollment, tok.PublicID); p != "lotor_enr_"+tok.PublicID[:6] {
		t.Fatalf("préfixe affiché %q", p)
	}
	if DisplayPrefix(Agent, "abc") != "lotor_agt_abc" {
		t.Fatal("identifiant court")
	}
}
