package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestServer(t *testing.T, public http.Handler, shutdown time.Duration, tlsCfg *tls.Config) (*Server, *atomic.Bool) {
	t.Helper()
	drained := &atomic.Bool{}
	s := NewServer(ServerOptions{
		PublicAddr:     "127.0.0.1:0",
		ManagementAddr: "127.0.0.1:0",
		Public:         public,
		Management:     http.NotFoundHandler(),
		TLS:            tlsCfg,
		Timeouts:       Timeouts{ReadHeader: time.Second, Shutdown: shutdown},
		Logger:         slog.New(slog.DiscardHandler),
		OnShutdown:     func() { drained.Store(true) },
	})
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	return s, drained
}

// TestGracefulShutdownLetsInFlightRequestsFinish : après l'annulation (SIGTERM), une
// requête en cours finit normalement, et l'instance cesse d'accepter des connexions.
func TestGracefulShutdownLetsInFlightRequestsFinish(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "fini")
	})
	s, drained := newTestServer(t, h, 5*time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()

	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + s.PublicAddr() + "/")
		if err != nil {
			got <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		got <- result{string(b), err}
	}()
	<-entered
	cancel()

	// L'écoute se ferme : une nouvelle connexion est refusée.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", s.PublicAddr(), 100*time.Millisecond)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("l'écoute accepte encore des connexions après l'arrêt")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !drained.Load() {
		t.Error("OnShutdown non appelé")
	}
	close(release)
	if r := <-got; r.err != nil || r.body != "fini" {
		t.Fatalf("requête en cours : %q, %v", r.body, r.err)
	}
	if err := <-runErr; err != nil {
		t.Fatalf("Run : %v", err)
	}
}

func TestShutdownTimeoutIsBounded(t *testing.T) {
	entered := make(chan struct{})
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-block
	})
	s, _ := newTestServer(t, h, 150*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()
	go func() {
		if resp, err := http.Get("http://" + s.PublicAddr() + "/"); err == nil {
			resp.Body.Close()
		}
	}()
	<-entered
	start := time.Now()
	cancel()
	err := <-runErr
	if err == nil || !strings.Contains(err.Error(), "arrêt forcé") {
		t.Fatalf("Run = %v, attendu un arrêt forcé", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("arrêt en %s, délai configuré 150 ms", d)
	}
}

func TestListenFailsOnBusyAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := NewServer(ServerOptions{PublicAddr: ln.Addr().String(), ManagementAddr: "127.0.0.1:0",
		Public: http.NotFoundHandler(), Management: http.NotFoundHandler(), Logger: slog.New(slog.DiscardHandler)})
	if err := s.Listen(); err == nil {
		t.Fatal("adresse occupée acceptée")
	}
	s = NewServer(ServerOptions{PublicAddr: "127.0.0.1:0", ManagementAddr: ln.Addr().String(),
		Public: http.NotFoundHandler(), Management: http.NotFoundHandler(), Logger: slog.New(slog.DiscardHandler)})
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("adresse de gestion occupée acceptée")
	}
}

// writeCert écrit un certificat autosigné pour 127.0.0.1 et sa clé.
func writeCert(t *testing.T, dir, name string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

func TestNativeTLSAndClientCertificates(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, serverCert := writeCert(t, dir, "server")
	caFile, caKey, caCert := writeCert(t, dir, "agent")
	cfg, err := TLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	var sawClientCert atomic.Bool
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawClientCert.Store(r.TLS != nil && len(r.TLS.PeerCertificates) == 1)
		_, _ = io.WriteString(w, "ok")
	})
	s, _ := newTestServer(t, h, time.Second, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	roots := x509.NewCertPool()
	roots.AddCert(serverCert)
	agentPair, err := tls.LoadX509KeyPair(caFile, caKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = caCert
	for _, withCert := range []bool{false, true} {
		tc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if withCert {
			tc.Certificates = []tls.Certificate{agentPair}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}
		resp, err := client.Get("https://" + s.PublicAddr() + "/")
		if err != nil {
			t.Fatalf("client (certificat : %v) : %v", withCert, err)
		}
		resp.Body.Close()
		if sawClientCert.Load() != withCert {
			t.Fatalf("certificat client vu = %v, attendu %v", sawClientCert.Load(), withCert)
		}
	}
	// Un certificat client d'une autre autorité est refusé.
	_, _, _ = writeCert(t, dir, "intruder")
	intruder, err := tls.LoadX509KeyPair(filepath.Join(dir, "intruder.pem"), filepath.Join(dir, "intruder-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// Le client Go n'envoie pas de lui-même un certificat d'une autorité que le serveur
	// n'annonce pas : on le force.
	force := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &intruder, nil }}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: force}, Timeout: 5 * time.Second}
	if resp, err := client.Get("https://" + s.PublicAddr() + "/"); err == nil {
		resp.Body.Close()
		t.Fatal("certificat client d'une autorité inconnue accepté")
	}
}

func TestTLSConfigErrors(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeCert(t, dir, "server")
	if _, err := TLSConfig(filepath.Join(dir, "absent.pem"), keyFile, ""); err == nil || !strings.Contains(err.Error(), "tls.cert_file") {
		t.Fatalf("certificat absent : %v", err)
	}
	if _, err := TLSConfig(certFile, keyFile, filepath.Join(dir, "absent.pem")); err == nil || !strings.Contains(err.Error(), "tls.client_ca_file") {
		t.Fatalf("autorité absente : %v", err)
	}
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("rien"), 0o600)
	if _, err := TLSConfig(certFile, keyFile, empty); err == nil {
		t.Fatal("autorité sans certificat acceptée")
	}
	cfg, err := TLSConfig(certFile, keyFile, "")
	if err != nil || cfg.MinVersion != tls.VersionTLS12 || cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("TLS sans mTLS : %+v, %v", cfg, err)
	}
}
