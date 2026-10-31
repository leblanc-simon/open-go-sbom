package sbom

import "errors"

// Clés d'erreur d'un SBOM refusé, traduites par <clé>.title et <clé>.text. Elles sont
// stockées avec l'ingestion en échec et renvoyées aux agents.
const (
	KeyTooLarge          = "error.ingest.too_large"
	KeyTooDeep           = "error.ingest.too_deep"
	KeyTooManyComponents = "error.ingest.too_many_components"
	KeyMalformed         = "error.ingest.malformed"
	KeyUnsupportedFormat = "error.ingest.unsupported_format"
	KeySchemaInvalid     = "error.ingest.schema_invalid"
	KeyDecodeFailed      = "error.ingest.decode_failed"
)

// ErrorKeys liste les clés d'erreur du paquet (tests de traduction).
func ErrorKeys() []string {
	return []string{KeyTooLarge, KeyTooDeep, KeyTooManyComponents, KeyMalformed, KeyUnsupportedFormat,
		KeySchemaInvalid, KeyDecodeFailed}
}

// Error est le refus d'un SBOM : la clé traduisible et, au besoin, un détail sans contenu
// du document (pointeur JSON d'une violation de schéma, version refusée).
type Error struct {
	Key    string
	Detail string
	err    error
}

func (e *Error) Error() string {
	msg := "sbom: " + e.Key
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	return msg
}

func (e *Error) Unwrap() error { return e.err }

// Reject construit un refus de clé key ; cause, facultative, reste accessible par
// errors.Unwrap mais n'est jamais montrée à l'agent.
func Reject(key, detail string, cause error) *Error {
	return &Error{Key: key, Detail: detail, err: cause}
}

// AsError renvoie le refus porté par err, s'il y en a un.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
