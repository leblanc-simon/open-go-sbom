package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
)

// RequestIDHeader porte l'identifiant de requête dans la réponse.
const RequestIDHeader = "X-Request-Id"

type requestIDKey struct{}

type loggerKey struct{}

// RequestID attribue à chaque requête un identifiant aléatoire, renvoyé dans l'en-tête
// X-Request-Id. Un identifiant fourni par le client est ignoré : il finirait tel quel dans
// les journaux.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand.Read ne renvoie jamais d'erreur (Go ≥ 1.24)
	return hex.EncodeToString(b)
}

// RequestIDFrom renvoie l'identifiant de la requête, ou "" hors RequestID.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Logger renvoie le journal de la requête (avec request_id), posé par AccessLog, ou
// fallback.
func Logger(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return l
	}
	return fallback
}
