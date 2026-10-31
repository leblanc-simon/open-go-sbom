package secret

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, keySize) }

func newBox(t *testing.T, active string, ids ...string) *Box {
	t.Helper()
	keys := map[string][]byte{}
	for i, id := range ids {
		keys[id] = key(byte(i + 1))
	}
	b, err := New(keys, active)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	b := newBox(t, "k1", "k1")
	aad := []byte("notification_channel:42")
	for _, pt := range [][]byte{[]byte("jeton-très-secret"), {}, bytes.Repeat([]byte{0xff}, 4096)} {
		ct, id, err := b.Seal(pt, aad)
		if err != nil || id != "k1" {
			t.Fatalf("Seal : %v, %q", err, id)
		}
		if len(pt) > 0 && bytes.Contains(ct, pt) {
			t.Fatal("le clair apparaît dans le chiffré")
		}
		got, err := b.Open(ct, id, aad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("Open = %q, %v", got, err)
		}
	}
}

func TestSealUsesFreshNonces(t *testing.T) {
	b := newBox(t, "k1", "k1")
	a, _, _ := b.Seal([]byte("x"), nil)
	c, _, _ := b.Seal([]byte("x"), nil)
	if bytes.Equal(a, c) {
		t.Fatal("deux chiffrés identiques pour le même clair")
	}
	if a[0] != formatV1 {
		t.Fatalf("version de format = %d", a[0])
	}
}

func TestOpenRefusesTampering(t *testing.T) {
	b := newBox(t, "k1", "k1", "k2")
	ct, id, err := b.Seal([]byte("secret"), []byte("row:1"))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		c := bytes.Clone(ct)
		c[i] ^= 0x01
		return c
	}
	cases := map[string]struct {
		ct    []byte
		keyID string
		aad   []byte
		want  error
	}{
		"octet du chiffré modifié": {flip(len(ct) - 1), id, []byte("row:1"), ErrInvalidCiphertext},
		"nonce modifié":            {flip(1), id, []byte("row:1"), ErrInvalidCiphertext},
		"version inconnue":         {append([]byte{2}, ct[1:]...), id, []byte("row:1"), ErrInvalidCiphertext},
		"tronqué":                  {ct[:10], id, []byte("row:1"), ErrInvalidCiphertext},
		"vide":                     {nil, id, []byte("row:1"), ErrInvalidCiphertext},
		"autre ligne":              {ct, id, []byte("row:2"), ErrInvalidCiphertext},
		"autre clé déclarée":       {ct, "k2", []byte("row:1"), ErrInvalidCiphertext},
		"clé inconnue":             {ct, "k9", []byte("row:1"), ErrUnknownKey},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := b.Open(c.ct, c.keyID, c.aad); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, attendu %v", err, c.want)
			}
		})
	}
}

func TestRotation(t *testing.T) {
	old := newBox(t, "2025", "2025")
	ct, id, err := old.Seal([]byte("secret"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	// Nouvelle clé active ; l'ancienne reste pour déchiffrer.
	b, err := New(map[string][]byte{"2025": key(1), "2026": key(2)}, "2026")
	if err != nil {
		t.Fatal(err)
	}
	if !b.NeedsRotation(id) || b.NeedsRotation("2026") {
		t.Fatal("NeedsRotation incorrect")
	}
	if got, err := b.Open(ct, id, []byte("ctx")); err != nil || string(got) != "secret" {
		t.Fatalf("ancienne clé : %q, %v", got, err)
	}
	ct2, id2, err := b.Rotate(ct, id, []byte("ctx"))
	if err != nil || id2 != "2026" {
		t.Fatalf("Rotate : %v, %q", err, id2)
	}
	// Une fois l'ancienne clé retirée, le chiffré rechiffré reste lisible.
	only, err := New(map[string][]byte{"2026": key(2)}, "2026")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := only.Open(ct2, id2, []byte("ctx")); err != nil || string(got) != "secret" {
		t.Fatalf("après retrait : %q, %v", got, err)
	}
	if _, err := only.Open(ct, id, []byte("ctx")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("ancien chiffré : err = %v", err)
	}
	if _, _, err := only.Rotate(ct, id, []byte("ctx")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Rotate sans l'ancienne clé : err = %v", err)
	}
}

func TestNewValidatesKeys(t *testing.T) {
	cases := map[string]struct {
		keys   map[string][]byte
		active string
	}{
		"aucune clé":         {map[string][]byte{}, "k1"},
		"clé active absente": {map[string][]byte{"k1": key(1)}, "k2"},
		"clé trop courte":    {map[string][]byte{"k1": key(1)[:16]}, "k1"},
		"nom invalide":       {map[string][]byte{"K 1": key(1)}, "K 1"},
		"nom trop long":      {map[string][]byte{"k123456789012345678901234567890123": key(1)}, "k123456789012345678901234567890123"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(c.keys, c.active); err == nil {
				t.Fatal("accepté")
			}
		})
	}
}

func TestParse(t *testing.T) {
	raw := key(7)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := Parse(map[string]string{"k1": " " + enc.EncodeToString(raw) + "\n"}, "k1")
		if err != nil {
			t.Fatalf("Parse : %v", err)
		}
		if b.ActiveKeyID() != "k1" || len(b.KeyIDs()) != 1 {
			t.Fatalf("Box = %v", b.KeyIDs())
		}
	}
	if _, err := Parse(map[string]string{"k1": "pas du base64 !"}, "k1"); err == nil {
		t.Fatal("base64 invalide accepté")
	}
	if _, err := Parse(map[string]string{"k1": base64.StdEncoding.EncodeToString([]byte("court"))}, "k1"); err == nil {
		t.Fatal("clé courte acceptée")
	}
}
