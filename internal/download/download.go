// Package download télécharge des ressources HTTP(S) pour le serveur (base de
// vulnérabilités). Le métier n'ouvre aucune connexion : il reçoit un Fetcher, que ce
// paquet implémente. Mandataire pris dans l'environnement (HTTPS_PROXY…), TLS par défaut
// de Go, taille bornée, contexte respecté.
package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"leblanc.io/lotor/internal/vuln"
)

// Client télécharge par HTTP(S).
type Client struct {
	http      *http.Client
	userAgent string
}

// New renvoie un Client. timeout borne un téléchargement entier (0 : sans borne autre que
// le contexte).
func New(userAgent string, timeout time.Duration) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = time.Minute
	return &Client{http: &http.Client{Transport: t, Timeout: timeout}, userAgent: userAgent}
}

var _ vuln.Fetcher = (*Client)(nil)

// Fetch écrit dans w le corps de la réponse à GET url, au plus maxBytes octets
// (vuln.ErrTooLarge au-delà). Seules les réponses 200 sont acceptées.
func (c *Client) Fetch(ctx context.Context, url string, w io.Writer, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s : statut %d", req.URL.Redacted(), resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return vuln.ErrTooLarge
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("download: lecture : %w", err)
	}
	if n > maxBytes {
		return vuln.ErrTooLarge
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return errors.New("download: réponse tronquée")
	}
	return nil
}
