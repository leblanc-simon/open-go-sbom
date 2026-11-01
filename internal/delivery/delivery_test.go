package delivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"leblanc.io/lotor/internal/notify"
)

func TestForbiddenAddresses(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "10.1.2.3": true, "172.16.0.1": true, "192.168.1.1": true, "169.254.169.254": true,
		"100.64.0.1": true, "0.0.0.0": true, "0.1.2.3": true, "fe80::1": true, "fc00::1": true, "::ffff:127.0.0.1": true,
		"224.0.0.1": true, "::": true, "93.184.216.34": false, "2606:4700::1111": false, "1.1.1.1": false,
	} {
		if got := Forbidden(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s : %v", addr, got)
		}
	}
}

func sendErrKey(err error) string {
	var se *notify.SendError
	if errors.As(err, &se) {
		return se.Key
	}
	return ""
}

func TestHTTPGuardStatusAndRedirects(t *testing.T) {
	var got http.Header
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			got = r.Header.Clone()
			b, _ := io.ReadAll(r.Body)
			body = string(b)
			w.WriteHeader(http.StatusNoContent)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	req := notify.Request{Method: http.MethodPost, URL: srv.URL + "/ok?token=secret", Header: map[string]string{"X-Test": "1"}, Body: []byte("{}")}

	// Garde par défaut : le serveur de test écoute sur le bouclage, refusé.
	err := New(Options{Timeout: 5 * time.Second}).Do(ctx, req)
	if sendErrKey(err) != notify.KeySendForbidden {
		t.Fatalf("bouclage accepté : %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("l'erreur cite l'URL : %v", err)
	}

	s := New(Options{Timeout: 5 * time.Second, AllowPrivate: true, UserAgent: "lotor/test"})
	if err := s.Do(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Test") != "1" || got.Get("User-Agent") != "lotor/test" || body != "{}" {
		t.Fatalf("requête reçue %v %q", got, body)
	}
	req.URL = srv.URL + "/redirect"
	if err := s.Do(ctx, req); sendErrKey(err) != notify.KeySendStatus {
		t.Fatalf("redirection suivie : %v", err)
	}
	req.URL = srv.URL + "/fail"
	if err := s.Do(ctx, req); sendErrKey(err) != notify.KeySendStatus {
		t.Fatalf("statut 500 : %v", err)
	}
	srv.Close()
	req.URL = srv.URL + "/ok"
	if err := s.Do(ctx, req); sendErrKey(err) != notify.KeySendUnreachable {
		t.Fatalf("serveur arrêté : %v", err)
	}
}

// fakeSMTP est un serveur SMTP de test minimal : EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT,
// DATA, QUIT. implicit sert TLS dès la connexion.
type fakeSMTP struct {
	ln       net.Listener
	cert     tls.Certificate
	implicit bool
	starttls bool
	reject   bool

	mu       sync.Mutex
	auth     string
	from     string
	rcpt     []string
	data     string
	secured  bool
	sessions int
}

func newFakeSMTP(t *testing.T, implicit, starttls bool) (*fakeSMTP, *tls.Config) {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	ts.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, cert: cert, implicit: implicit, starttls: starttls}
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.session(c)
	}
}

func (f *fakeSMTP) session(c net.Conn) {
	defer c.Close()
	tlsConf := &tls.Config{Certificates: []tls.Certificate{f.cert}}
	secured := false
	if f.implicit {
		c, secured = tls.Server(c, tlsConf), true
	}
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(s string) { _, _ = w.WriteString(s + "\r\n"); _ = w.Flush() }
	f.mu.Lock()
	f.sessions++
	f.mu.Unlock()
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch cmd {
		case "EHLO":
			if f.starttls && !secured {
				say("250-fake\r\n250-AUTH PLAIN\r\n250 STARTTLS")
			} else {
				say("250-fake\r\n250 AUTH PLAIN")
			}
		case "STARTTLS":
			say("220 go")
			tc := tls.Server(c, tlsConf)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, secured = tc, true
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
		case "AUTH":
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f.mu.Lock()
			f.auth, f.secured = string(raw), secured
			f.mu.Unlock()
			if strings.Contains(string(raw), "wrong") {
				say("535 bad credentials")
				continue
			}
			say("235 ok")
		case "MAIL":
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			say("250 ok")
		case "RCPT":
			f.mu.Lock()
			reject := f.reject
			f.mu.Unlock()
			if reject {
				say("550 no such user")
				continue
			}
			f.mu.Lock()
			f.rcpt = append(f.rcpt, line)
			f.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSMTPStartTLSAndImplicit(t *testing.T) {
	for _, mode := range []string{SMTPStartTLS, SMTPImplicit} {
		f, tlsConf := newFakeSMTP(t, mode == SMTPImplicit, mode == SMTPStartTLS)
		s := New(Options{Timeout: 5 * time.Second, SMTP: SMTPConfig{Host: "127.0.0.1", Port: f.port(), TLS: mode,
			Username: "lotor", Password: "pw", From: "lotor@example.org", TLSConfig: tlsConf}})
		err := s.Mail(context.Background(), notify.Mail{To: []string{"ops@example.org", "sec@example.org"},
			Subject: "lotor : alerte é\r\nBcc: evil@example.org", Text: "Ligne 1\nRègle « KEV »", MessageID: "abc"})
		if err != nil {
			t.Fatalf("%s : %v", mode, err)
		}
		f.mu.Lock()
		if !f.secured || f.auth != "\x00lotor\x00pw" || len(f.rcpt) != 2 || !strings.Contains(f.from, "lotor@example.org") {
			t.Errorf("%s : session %+v", mode, f)
		}
		data := f.data
		f.mu.Unlock()
		for _, want := range []string{"From: <lotor@example.org>", "To: <ops@example.org>, <sec@example.org>",
			"Subject: =?utf-8?q?", "Content-Type: text/plain; charset=utf-8", "Message-ID: <abc@example.org>", "R=C3=A8gle"} {
			if !strings.Contains(data, want) {
				t.Errorf("%s : %q absent de\n%s", mode, want, data)
			}
		}
		if strings.Contains(data, "\r\nBcc:") {
			t.Errorf("%s : en-tête injecté", mode)
		}
	}
}

func TestSMTPFailures(t *testing.T) {
	ctx := context.Background()
	mail := notify.Mail{To: []string{"ops@example.org"}, Subject: "s", Text: "t", MessageID: "x"}
	if err := New(Options{}).Mail(ctx, mail); sendErrKey(err) != notify.KeySendUnconfigured {
		t.Errorf("sans SMTP : %v", err)
	}
	// STARTTLS exigé : un serveur qui ne le propose pas est refusé, avant tout mot de passe.
	f, tlsConf := newFakeSMTP(t, false, false)
	cfg := SMTPConfig{Host: "127.0.0.1", Port: f.port(), TLS: SMTPStartTLS, Username: "lotor", Password: "pw",
		From: "lotor@example.org", TLSConfig: tlsConf}
	if err := New(Options{Timeout: 5 * time.Second, SMTP: cfg}).Mail(ctx, mail); sendErrKey(err) != notify.KeySendSMTP {
		t.Errorf("sans STARTTLS : %v", err)
	}
	f.mu.Lock()
	if f.auth != "" {
		t.Error("mot de passe envoyé en clair")
	}
	f.mu.Unlock()
	f2, tlsConf2 := newFakeSMTP(t, false, true)
	cfg2 := SMTPConfig{Host: "127.0.0.1", Port: f2.port(), TLS: SMTPStartTLS, Username: "lotor", Password: "wrong",
		From: "lotor@example.org", TLSConfig: tlsConf2}
	err := New(Options{Timeout: 5 * time.Second, SMTP: cfg2}).Mail(ctx, mail)
	if sendErrKey(err) != notify.KeySendSMTP || strings.Contains(err.Error(), "wrong") {
		t.Errorf("mauvais mot de passe : %v", err)
	}
	f2.mu.Lock()
	f2.reject = true
	f2.mu.Unlock()
	cfg2.Password = "pw"
	if err := New(Options{Timeout: 5 * time.Second, SMTP: cfg2}).Mail(ctx, mail); sendErrKey(err) != notify.KeySendSMTP {
		t.Errorf("destinataire refusé : %v", err)
	}
	cfg2.Port = closedPort(t)
	if err := New(Options{Timeout: 2 * time.Second, SMTP: cfg2}).Mail(ctx, mail); sendErrKey(err) != notify.KeySendSMTP {
		t.Errorf("serveur arrêté : %v", err)
	}
}

func closedPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}
