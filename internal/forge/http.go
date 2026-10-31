package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxResponse borne la lecture d'une réponse d'API de forge (une comparaison de GitHub
// liste jusqu'à 250 commits et 300 fichiers).
const maxResponse = 16 << 20

// DefaultTimeout est le délai d'un appel d'API de forge quand le client n'en fixe pas.
const DefaultTimeout = 30 * time.Second

func defaultClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: DefaultTimeout}
}

// call envoie une requête d'API et décode sa réponse JSON dans out (si non nil). Les
// en-têtes portent l'authentification : ils ne figurent jamais dans l'erreur, qui ne cite
// que la méthode, le chemin et le statut.
func call(ctx context.Context, client *http.Client, method, rawURL string, header http.Header, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("forge: encodage de la requête : %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return fmt.Errorf("forge: requête %s : %w", method, err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		// L'erreur de transport cite l'URL, qui ne porte jamais d'identifiants.
		return fmt.Errorf("forge: %s %s : %w", method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("forge: %s %s : lecture : %w", method, req.URL.Path, err)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("forge: %s %s : réponse trop volumineuse", method, req.URL.Path)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w (%s %s)", ErrNotFound, method, req.URL.Path)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w (%s %s : %d)", ErrDenied, method, req.URL.Path, resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return fmt.Errorf("forge: %s %s : statut %d", method, req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("forge: %s %s : réponse illisible : %w", method, req.URL.Path, err)
	}
	return nil
}
