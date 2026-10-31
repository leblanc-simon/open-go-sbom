package agentclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"leblanc.io/lotor/internal/agentclient/gen"
)

// pki est une autorité de test et ce qu'elle signe.
type pki struct {
	t    *testing.T
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T, name string) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p := &pki{t: t, dir: t.TempDir(), cert: cert, key: key, pool: x509.NewCertPool()}
	p.pool.AddCert(cert)
	p.write("ca.pem", "CERTIFICATE", der)
	return p
}

func (p *pki) write(name, typ string, der []byte) string {
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}

// issue signe un certificat (serveur pour 127.0.0.1, ou client) et l'écrit avec sa clé.
func (p *pki) issue(name string, server bool) (certFile, keyFile string, cert tls.Certificate) {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	certFile, keyFile = p.write(name+".pem", "CERTIFICATE", der), p.write(name+".key", "EC PRIVATE KEY", kder)
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		p.t.Fatal(err)
	}
	return certFile, keyFile, cert
}

// tlsServer démarre un serveur HTTPS signé par ca ; clients, si non nil, exige un
// certificat client de cette autorité.
func tlsServer(t *testing.T, ca *pki, clients *x509.CertPool) (*httptest.Server, chan string) {
	t.Helper()
	seen := make(chan string, 10)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := ""
		if len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		seen <- cn
		writeJSON(w, http.StatusOK, gen.HeartbeatStatus{ServerTime: time.Now()})
	}))
	_, _, cert := ca.issue("server", true)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if clients != nil {
		srv.TLS.ClientCAs, srv.TLS.ClientAuth = clients, tls.RequireAndVerifyClientCert
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestPrivateCAIsTrusted(t *testing.T) {
	ca := newPKI(t, "ca-privee")
	srv, _ := tlsServer(t, ca, nil)
	noRetry := Retry{Attempts: 1}
	c, err := New(Options{ServerURL: srv.URL, Token: "t", TLS: TLSOptions{CAFile: filepath.Join(ca.dir, "ca.pem")}, Retry: noRetry})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err != nil {
		t.Fatalf("autorité privée : %v", err)
	}
	other := newPKI(t, "autre")
	c, err = New(Options{ServerURL: srv.URL, Token: "t", TLS: TLSOptions{CAFile: filepath.Join(other.dir, "ca.pem")}, Retry: noRetry})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err == nil {
		t.Error("serveur d'une autre autorité accepté")
	}
}

func TestClientCertificateIsPresentedAndReloaded(t *testing.T) {
	ca := newPKI(t, "ca")
	clients := newPKI(t, "clients")
	srv, seen := tlsServer(t, ca, clients.pool)
	certFile, keyFile, _ := clients.issue("agent-1", false)
	c, err := New(Options{ServerURL: srv.URL, Token: "t", Retry: Retry{Attempts: 1},
		TLS: TLSOptions{CAFile: filepath.Join(ca.dir, "ca.pem"), ClientCertFile: certFile, ClientKeyFile: keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err != nil {
		t.Fatalf("mTLS : %v", err)
	}
	if cn := <-seen; cn != "agent-1" {
		t.Errorf("certificat présenté %q", cn)
	}
	// Renouvellement sur le disque : le prochain échange présente le nouveau certificat.
	newCert, newKey, _ := clients.issue("agent-1-renouvele", false)
	for _, mv := range [][2]string{{newCert, certFile}, {newKey, keyFile}} {
		data, _ := os.ReadFile(mv[0])
		if err := os.WriteFile(mv[1], data, 0o600); err != nil {
			t.Fatal(err)
		}
		future := time.Now().Add(time.Minute)
		_ = os.Chtimes(mv[1], future, future)
	}
	c.doer.client.Transport.(*http.Transport).CloseIdleConnections()
	if _, err := c.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if cn := <-seen; cn != "agent-1-renouvele" {
		t.Errorf("certificat renouvelé non relu : %q", cn)
	}

	noCert, err := New(Options{ServerURL: srv.URL, Token: "t", Retry: Retry{Attempts: 1},
		TLS: TLSOptions{CAFile: filepath.Join(ca.dir, "ca.pem")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noCert.Heartbeat(context.Background(), gen.HeartbeatRequest{Version: "1"}); err == nil {
		t.Error("connexion sans certificat client acceptée")
	}
}

func TestTransportOptionsAreValidated(t *testing.T) {
	ca := newPKI(t, "ca")
	certFile, keyFile, _ := ca.issue("c", false)
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("pas un certificat"), 0o600)
	for name, o := range map[string]Options{
		"autorité absente":   {TLS: TLSOptions{CAFile: filepath.Join(t.TempDir(), "absent.pem")}},
		"autorité illisible": {TLS: TLSOptions{CAFile: bad}},
		"certificat seul":    {TLS: TLSOptions{ClientCertFile: certFile}},
		"clé seule":          {TLS: TLSOptions{ClientKeyFile: keyFile}},
		"paire invalide":     {TLS: TLSOptions{ClientCertFile: bad, ClientKeyFile: keyFile}},
		"mandataire":         {Proxy: "pas une url"},
	} {
		o.ServerURL = "https://sbom.example.org"
		if _, err := New(o); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if _, err := New(Options{ServerURL: "https://sbom.example.org", Proxy: "http://proxy.example.org:3128",
		TLS: TLSOptions{ClientCertFile: certFile, ClientKeyFile: keyFile}}); err != nil {
		t.Errorf("options valides refusées : %v", err)
	}
}
