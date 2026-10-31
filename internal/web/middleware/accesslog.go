package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// AccessLog journalise chaque requête : méthode, chemin (sans la requête, qui peut porter
// des termes de recherche), motif de route, statut, taille, durée et IP du client. Les
// erreurs serveur sont au niveau error. Il place dans le contexte un journal qui porte
// request_id (voir Logger).
func AccessLog(logger *slog.Logger, clientIP func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqLogger := logger.With("request_id", RequestIDFrom(r.Context()))
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			r = r.WithContext(context.WithValue(r.Context(), loggerKey{}, reqLogger))
			next.ServeHTTP(ww, r)

			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			level := slog.LevelInfo
			if status >= 500 {
				level = slog.LevelError
			}
			reqLogger.LogAttrs(r.Context(), level, "requête",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("route", routePattern(r)),
				slog.Int("status", status),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Duration("duration", time.Since(start)),
				slog.String("ip", clientIP(r)),
			)
		})
	}
}

// routePattern renvoie le motif chi de la route servie (/o/{org}/projects), borné en
// cardinalité, ou « unmatched ».
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "unmatched"
}
