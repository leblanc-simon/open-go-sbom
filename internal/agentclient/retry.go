package agentclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Retry règle les réessais d'un appel.
type Retry struct {
	// Attempts est le nombre total de tentatives, première comprise (défaut 5).
	Attempts int
	// Base est le délai après le premier échec, doublé à chaque tentative (défaut 1 s).
	Base time.Duration
	// Max plafonne le délai entre deux tentatives, Retry-After compris (défaut 5 min).
	Max time.Duration
}

// DefaultRetry est la politique par défaut : 5 tentatives, de 1 s à 5 min.
var DefaultRetry = Retry{Attempts: 5, Base: time.Second, Max: 5 * time.Minute}

func (r Retry) withDefaults() Retry {
	if r.Attempts <= 0 {
		r.Attempts = DefaultRetry.Attempts
	}
	if r.Base <= 0 {
		r.Base = DefaultRetry.Base
	}
	if r.Max <= 0 {
		r.Max = DefaultRetry.Max
	}
	r.Max = max(r.Max, r.Base)
	return r
}

// backoff est le délai après l'échec de la tentative n (1 pour la première) : Base·2ⁿ⁻¹,
// plafonné à Max, tiré entre sa moitié et lui-même pour que des agents en panne en même
// temps ne reviennent pas ensemble.
func (r Retry) backoff(n int) time.Duration {
	d := r.Max
	if n-1 < 32 {
		if e := r.Base << (n - 1); e > 0 && e < r.Max {
			d = e
		}
	}
	half := d / 2
	return half + rand.N(d-half+1)
}

// retryable dit si un statut appelle un réessai : débit dépassé ou serveur
// momentanément indisponible.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter lit Retry-After (secondes, ou date HTTP) relativement à now.
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// maxResponse borne le corps d'une réponse lu par le client.
const maxResponse = 8 << 20

// errResponseTooLarge : réponse au-delà de maxResponse.
var errResponseTooLarge = errors.New("agentclient: réponse trop longue")

type opKey struct{}

// withOp nomme l'opération dans le contexte, pour les journaux des réessais.
func withOp(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, opKey{}, op)
}

func opOf(ctx context.Context) string {
	op, _ := ctx.Value(opKey{}).(string)
	return op
}

// retryDoer exécute une requête avec les réessais de sa politique. Le corps d'une
// requête est rejoué par GetBody, que net/http pose pour un corps en mémoire.
type retryDoer struct {
	client *http.Client
	retry  Retry
	logger *slog.Logger
	sleep  func(context.Context, time.Duration) error
}

func (d *retryDoer) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	for attempt := 1; ; attempt++ {
		r, err := rewind(req, attempt)
		if err != nil {
			return nil, err
		}
		rsp, err := d.client.Do(r)
		last := attempt >= d.retry.Attempts
		var wait time.Duration
		switch {
		case err != nil:
			if ctx.Err() != nil || last {
				return nil, err
			}
			wait = d.retry.backoff(attempt)
		case !retryable(rsp.StatusCode) || last:
			rsp.Body = &limitedBody{r: io.LimitReader(rsp.Body, maxResponse+1), c: rsp.Body}
			return rsp, nil
		default:
			wait = d.retry.backoff(attempt)
			if ra, ok := retryAfter(rsp.Header, time.Now()); ok {
				if ra > d.retry.Max {
					// Attendre au-delà de la politique bloquerait l'agent : l'appel échoue
					// et l'appelant reprendra à son prochain cycle.
					rsp.Body = &limitedBody{r: io.LimitReader(rsp.Body, maxResponse+1), c: rsp.Body}
					return rsp, nil
				}
				wait = ra
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(rsp.Body, maxResponse))
			_ = rsp.Body.Close()
		}
		if d.logger != nil {
			attrs := []any{"op", opOf(ctx), "attempt", attempt, "wait", wait.String()}
			if rsp != nil {
				attrs = append(attrs, "status", rsp.StatusCode)
			} else {
				attrs = append(attrs, "err", err.Error())
			}
			d.logger.WarnContext(ctx, "appel de l'API réessayé", attrs...)
		}
		if err := d.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// rewind prépare la tentative attempt : la requête d'origine d'abord, puis une copie au
// corps rejoué.
func rewind(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 1 || req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("agentclient: corps de requête impossible à rejouer")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context())
	r.Body = body
	return r, nil
}

// limitedBody lit au plus maxResponse octets et signale un dépassement par une erreur
// plutôt que par une troncature silencieuse.
type limitedBody struct {
	r io.Reader
	c io.Closer
	n int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	if b.n > maxResponse {
		return n, errResponseTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.c.Close() }
