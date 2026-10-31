package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recover transforme une panique d'un handler en réponse onPanic (page ou problème 500),
// si rien n'a encore été écrit, et la journalise avec sa pile. http.ErrAbortHandler est
// relancée : c'est la façon voulue d'interrompre une réponse.
func Recover(logger *slog.Logger, onPanic http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tw := &trackingWriter{ResponseWriter: w}
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec)
				}
				Logger(r.Context(), logger).Error("panique dans un handler",
					"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				if !tw.wrote {
					onPanic.ServeHTTP(w, r)
				}
			}()
			next.ServeHTTP(tw, r)
		})
	}
}

// trackingWriter note si la réponse a commencé.
type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackingWriter) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

// Unwrap expose l'écrivain d'origine à http.ResponseController (Flush, délais).
func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }
