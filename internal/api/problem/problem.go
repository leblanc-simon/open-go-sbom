// Package problem écrit les erreurs de l'API au format RFC 9457
// (application/problem+json), décrit par le schéma Problem d'api/openapi.yaml.
//
// type porte une clé stable (error.not_found) que les clients comparent ; title et
// detail sont traduits selon la langue de la requête, depuis les clés <clé>.title et
// <clé>.text :
//
//	problem.Write(w, r, cat, http.StatusBadRequest, "error.invalid_limit", map[string]any{"Max": 200})
//	problem.FromPagination(w, r, cat, err) // erreurs de internal/pagination
//
// La réponse porte aussi l'identifiant de requête (request_id), repris dans les journaux.
package problem

import (
	"encoding/json"
	"errors"
	"net/http"

	"leblanc.io/open-go-base/i18n"

	"leblanc.io/lotor/internal/api/gen"
	"leblanc.io/lotor/internal/locale"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/web/middleware"
)

// ContentType est le type des réponses d'erreur.
const ContentType = "application/problem+json"

// Clés d'erreur génériques de l'API.
const (
	KeyNotFound         = "error.not_found"
	KeyMethodNotAllowed = "error.method_not_allowed"
	KeyTooManyRequests  = "error.too_many_requests"
	KeyInternal         = "error.internal"
	KeyInvalidCursor    = "error.invalid_cursor"
	KeyInvalidLimit     = "error.invalid_limit"
	KeyInvalidRequest   = "error.invalid_request"
	KeyValidation       = "error.validation"
	KeyUnauthorized     = "error.unauthorized"
)

// Keys liste les clés employées par ce paquet, pour les tests de traduction.
func Keys() []string {
	return []string{KeyNotFound, KeyMethodNotAllowed, KeyTooManyRequests, KeyInternal, KeyInvalidCursor, KeyInvalidLimit,
		KeyInvalidRequest, KeyValidation, KeyUnauthorized}
}

// Write écrit un problème de statut status et de clé key ; params alimente le texte.
func Write(w http.ResponseWriter, r *http.Request, cat *locale.Catalog, status int, key string, params map[string]any) {
	loc := middleware.Localizer(cat, r)
	detail := loc.T(key+".text", params)
	if params == nil {
		detail = loc.T(key + ".text")
	}
	write(w, r, loc, status, key, detail)
}

// WriteValidation écrit un problème 400 error.validation dont le détail est le message
// traduit de la clé de validation detailKey (validation.*).
func WriteValidation(w http.ResponseWriter, r *http.Request, cat *locale.Catalog, detailKey string) {
	loc := middleware.Localizer(cat, r)
	write(w, r, loc, http.StatusBadRequest, KeyValidation, loc.T(detailKey))
}

func write(w http.ResponseWriter, r *http.Request, loc *i18n.Localizer, status int, key, detail string) {
	instance := r.URL.Path
	p := gen.Problem{
		Type:     key,
		Title:    loc.T(key + ".title"),
		Status:   status,
		Detail:   &detail,
		Instance: &instance,
	}
	if id := middleware.RequestIDFrom(r.Context()); id != "" {
		p.RequestId = &id
	}
	body, err := json.Marshal(p)
	if err != nil {
		// Impossible avec des chaînes et un entier ; on garde une réponse valide.
		body = []byte(`{"type":"` + KeyInternal + `","title":"Internal Server Error","status":500}`)
		status = http.StatusInternalServerError
	}
	h := w.Header()
	h.Set("Content-Type", ContentType)
	h.Set("Content-Language", loc.Lang().String())
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Handler renvoie un handler qui écrit toujours le même problème (route inconnue,
// méthode refusée, panique récupérée).
func Handler(cat *locale.Catalog, status int, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Write(w, r, cat, status, key, nil)
	})
}

// FromPagination traduit une erreur de internal/pagination en problème 400 et indique
// si elle l'a fait.
func FromPagination(w http.ResponseWriter, r *http.Request, cat *locale.Catalog, err error) bool {
	var le *pagination.LimitError
	switch {
	case errors.As(err, &le):
		Write(w, r, cat, http.StatusBadRequest, KeyInvalidLimit, map[string]any{"Max": le.Max})
	case errors.Is(err, pagination.ErrInvalidCursor):
		Write(w, r, cat, http.StatusBadRequest, KeyInvalidCursor, nil)
	default:
		return false
	}
	return true
}
