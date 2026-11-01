// Package delivery envoie les notifications (T15, ADR 0046) : requêtes HTTP des webhooks,
// de Matrix, Slack et Mattermost, et courriels par SMTP (net/smtp). C'est un paquet serveur
// hors du métier, comme download : internal/notify compose les messages et ne connaît que
// son interface Sender.
//
// Une URL de canal est saisie par un administrateur d'organisation, qui n'est pas
// l'administrateur de l'instance : sans précaution, le serveur ferait des requêtes vers
// son propre réseau (SSRF). Le client HTTP refuse donc, au moment de la connexion (après
// la résolution DNS, si bien qu'un nom qui change d'adresse ne contourne rien), toute
// adresse de bouclage, privée, de lien local, partagée (100.64.0.0/10), non spécifiée ou
// de multidiffusion, sauf si l'exploitant l'autorise (notify.allow_private_networks). Il
// ne suit aucune redirection, ne passe par aucun mandataire, borne la durée de la requête
// et la lecture de la réponse, et n'écrit jamais l'URL ni les en-têtes (qui portent des
// secrets) dans une erreur.
package delivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"leblanc.io/lotor/internal/notify"
)

// Options règle les envois.
type Options struct {
	// Timeout borne une requête HTTP ou une session SMTP entière.
	Timeout time.Duration
	// AllowPrivate autorise les adresses privées et de bouclage (relais internes, tests).
	AllowPrivate bool
	UserAgent    string
	SMTP         SMTPConfig
}

// Sender implémente notify.Sender.
type Sender struct {
	o      Options
	client *http.Client
	dialer *net.Dialer
}

var _ notify.Sender = (*Sender)(nil)

// errForbidden : adresse refusée par la garde.
var errForbidden = errors.New("delivery: adresse refusée")

// cgnat est l'espace d'adresses partagé (RFC 6598), non couvert par netip.IsPrivate.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Forbidden indique une adresse que la garde refuse sans AllowPrivate.
func Forbidden(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || cgnat.Contains(a) ||
		(a.Is4() && a.As4()[0] == 0)
}

// New renvoie un Sender.
func New(o Options) *Sender {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "lotor"
	}
	d := &net.Dialer{Timeout: o.Timeout}
	if !o.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || Forbidden(ap.Addr()) {
				return errForbidden
			}
			return nil
		}
	}
	t := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Sender{o: o, dialer: d, client: &http.Client{Transport: t, Timeout: o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// maxResponse borne la lecture d'une réponse (elle n'est que vidée).
const maxResponse = 64 << 10

// Do envoie une requête ; tout statut hors 2xx est un échec (une redirection aussi).
func (s *Sender) Do(ctx context.Context, r notify.Request) error {
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return &notify.SendError{Key: notify.KeySendFailed, Err: errors.New("requête invalide")}
	}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", s.o.UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(err, errForbidden) {
			return &notify.SendError{Key: notify.KeySendForbidden, Err: errForbidden}
		}
		// L'erreur du client cite l'URL, qui peut être un secret (webhook Slack) : seule
		// sa nature est gardée.
		return &notify.SendError{Key: notify.KeySendUnreachable, Err: transportError(err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &notify.SendError{Key: notify.KeySendStatus, Err: fmt.Errorf("statut %d", resp.StatusCode)}
	}
	return nil
}

// transportError résume une erreur de transport sans l'URL.
func transportError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return errors.New("délai dépassé")
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return fmt.Errorf("connexion impossible (%s)", oe.Op)
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return errors.New("nom introuvable")
	}
	return errors.New("échec de la requête")
}
