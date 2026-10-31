package forge

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseGitRef(t *testing.T) {
	cases := map[string]Ref{
		"refs/heads/main":         {RefBranch, "main"},
		"refs/heads/feature/a-b":  {RefBranch, "feature/a-b"},
		"refs/tags/v1.2.0":        {RefTag, "v1.2.0"},
		"refs/tags/release/2026":  {RefTag, "release/2026"},
		"refs/heads/":             {},
		"refs/merge-requests/1/x": {},
		"main":                    {},
	}
	for in, want := range cases {
		got, ok := ParseGitRef(in)
		if ok != (want != Ref{}) || got != want {
			t.Errorf("ParseGitRef(%q) = %v, %v ; attendu %v", in, got, ok, want)
		}
	}
}

func TestValidCommit(t *testing.T) {
	sha1 := strings.Repeat("a1", 20)
	sha256 := strings.Repeat("b2", 32)
	for _, ok := range []string{sha1, sha256} {
		if !ValidCommit(ok) {
			t.Errorf("%q refusé", ok)
		}
	}
	for _, bad := range []string{"", "abc", strings.ToUpper(sha1), sha1 + "0", sha1[:39] + "g"} {
		if ValidCommit(bad) {
			t.Errorf("%q accepté", bad)
		}
	}
	if !zeroCommit(strings.Repeat("0", 40)) || zeroCommit("") || zeroCommit(sha1) {
		t.Error("zeroCommit")
	}
}

func TestCredentialsAreMasked(t *testing.T) {
	c := Credentials{Username: "x-access-token", Password: "ghs_secret"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s", c, c, c, c)} {
		if strings.Contains(s, "ghs_secret") || strings.Contains(s, "x-access-token") {
			t.Fatalf("identifiants affichés : %s", s)
		}
	}
}

func TestEscapeRef(t *testing.T) {
	if got := escapeRef("feature/a b#c"); got != "feature/a%20b%23c" {
		t.Fatal(got)
	}
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseRSAPrivateKey(t *testing.T) {
	k := testKey(t)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for name, data := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		got, err := ParseRSAPrivateKey(data)
		if err != nil || !got.Equal(k) {
			t.Errorf("%s : %v", name, err)
		}
	}
	bad := [][]byte{
		nil,
		[]byte("pas une clé"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2}}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}}),
	}
	for i, data := range bad {
		if _, err := ParseRSAPrivateKey(data); err == nil {
			t.Errorf("clé %d acceptée", i)
		}
	}
}

func TestAppJWT(t *testing.T) {
	k := testKey(t)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	tok, err := appJWT(k, "123456", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT en %d parties", len(parts))
	}
	enc := base64.RawURLEncoding
	var header map[string]string
	raw, _ := enc.DecodeString(parts[0])
	if err := json.Unmarshal(raw, &header); err != nil || header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("en-tête %s", raw)
	}
	var claims struct {
		Iat, Exp int64
		Iss      string
	}
	raw, _ = enc.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "123456" || claims.Iat != now.Add(-time.Minute).Unix() || claims.Exp != now.Add(9*time.Minute).Unix() {
		t.Fatalf("revendications %+v", claims)
	}
	// GitHub refuse un JWT de plus de dix minutes.
	if claims.Exp-claims.Iat > 600 {
		t.Fatal("durée de vie supérieure à dix minutes")
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature : %v", err)
	}
}
