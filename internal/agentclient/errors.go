package agentclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	"leblanc.io/open-go-sbom/internal/agentclient/gen"
)

// Error est une réponse du serveur hors 2xx. Key est la clé stable du problème RFC 9457
// (error.ingest.too_large, error.token.revoked…), vide si la réponse n'en était pas un
// (mandataire intermédiaire, par exemple) ; Title et Detail sont traduits selon
// Options.Language.
type Error struct {
	Op        string
	Status    int
	Key       string
	Title     string
	Detail    string
	RequestID string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("agentclient: %s : statut %d", e.Op, e.Status)
	if e.Key != "" {
		msg += " " + e.Key
	}
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	if e.RequestID != "" {
		msg += " [requête " + e.RequestID + "]"
	}
	return msg
}

// IsKey dit si err est une réponse du serveur de clé key.
func IsKey(err error, key string) bool {
	var e *Error
	return errors.As(err, &e) && e.Key == key
}

// HasStatus dit si err est une réponse du serveur de statut status.
func HasStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Clés d'erreur du serveur qu'un agent traite à part.
const (
	// KeyTooLarge : SBOM au-delà de la taille admise (413).
	KeyTooLarge = "error.ingest.too_large"
	// KeyRefUnknown : référence non confiée à l'agent (404).
	KeyRefUnknown = "error.ingest.ref_unknown"
	// KeyTokenInvalid, KeyTokenRevoked, KeyTokenExpired, KeyAgentDisabled : jeton refusé
	// (401) ; l'agent ne peut rien sans intervention.
	KeyTokenInvalid  = "error.token.invalid"
	KeyTokenRevoked  = "error.token.revoked"
	KeyTokenExpired  = "error.token.expired"
	KeyAgentDisabled = "error.agent.disabled"
)

// responseError construit l'erreur d'une réponse inattendue.
func responseError(op string, rsp *http.Response, body []byte) error {
	e := &Error{Op: op}
	if rsp != nil {
		e.Status = rsp.StatusCode
		mt, _, _ := mime.ParseMediaType(rsp.Header.Get("Content-Type"))
		if mt == "application/problem+json" || mt == "application/json" {
			var p gen.Problem
			if json.Unmarshal(body, &p) == nil {
				e.Key, e.Title = p.Type, p.Title
				if p.Detail != nil {
					e.Detail = *p.Detail
				}
				if p.RequestId != nil {
					e.RequestID = *p.RequestId
				}
			}
		}
	}
	return e
}

func wrapTransport(op string, err error) error {
	return fmt.Errorf("agentclient: %s : %w", op, err)
}
