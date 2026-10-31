package repoagent

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"unicode"

	"leblanc.io/open-go-base/ratelimit"

	"leblanc.io/open-go-sbom/internal/forge"
)

// PushHandler reçoit un push vérifié ; faux si le travail n'a pas pu être mis en file.
type PushHandler func(forgeName string, p forge.Push) bool

// Receiver est le récepteur de webhooks, exposé à Internet : POST /webhooks/<forge>.
// Il borne le corps, vérifie la signature avant toute lecture du contenu, écarte les
// livraisons déjà reçues et répond aussitôt ; le traitement est asynchrone (file).
type Receiver struct {
	forges  map[string]forge.Provider
	onPush  PushHandler
	maxBody int64
	log     *slog.Logger
	seen    *boundedSet
	limiter *ratelimit.Limiter
}

// NewReceiver construit le récepteur. rateLimit compte les requêtes par minute et par IP
// (0 : sans limite) ; trustedProxies liste les mandataires dont X-Forwarded-For est cru.
func NewReceiver(forges []forge.Provider, onPush PushHandler, maxBody int64, rateLimit int, trustedProxies []string, log *slog.Logger) (*Receiver, error) {
	lim, err := ratelimit.New(rateLimit, trustedProxies)
	if err != nil {
		return nil, err
	}
	m := map[string]forge.Provider{}
	for _, f := range forges {
		m[f.Name()] = f
	}
	return &Receiver{forges: m, onPush: onPush, maxBody: maxBody, log: log, seen: newBoundedSet(10_000), limiter: lim}, nil
}

// Handler renvoie les routes du récepteur : les webhooks, limités en débit, et
// GET /healthz pour la sonde de vie.
func (rc *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /webhooks/{forge}", rc.limiter.Middleware(http.HandlerFunc(rc.serveWebhook)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

func (rc *Receiver) serveWebhook(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("forge")
	f, ok := rc.forges[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	log := rc.log.With("forge", name, "remote", rc.limiter.ClientIP(r))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, rc.maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			log.Warn("webhook refusé : corps trop volumineux")
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	push, err := f.VerifyWebhook(r.Header, body)
	switch {
	case errors.Is(err, forge.ErrSignature):
		// Journalisé sans le contenu ni les en-têtes, qui ne sont pas authentifiés.
		log.Warn("webhook refusé : signature invalide", "size", len(body))
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	case err != nil:
		log.Warn("webhook signé mais illisible")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	case push == nil:
		w.WriteHeader(http.StatusNoContent)
		return
	}
	delivery := printable(push.Delivery)
	if delivery != "" && !rc.seen.add(name+"\x00"+delivery) {
		log.Info("webhook déjà reçu, ignoré", "delivery", delivery)
		w.WriteHeader(http.StatusOK)
		return
	}
	if !rc.onPush(name, *push) {
		log.Warn("file pleine : push reporté au prochain rattrapage", "delivery", delivery)
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	log.Info("push reçu", "delivery", delivery, "repo", printable(push.Repo), "ref", printable(push.Ref.Name))
	w.WriteHeader(http.StatusAccepted)
}

// printable borne une valeur venue d'un webhook avant de la journaliser : 128
// caractères imprimables au plus.
func printable(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if len(out) == 128 {
			break
		}
		if unicode.IsPrint(r) {
			out = append(out, r)
		}
	}
	return string(out)
}
