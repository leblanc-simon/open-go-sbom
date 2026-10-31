package agent

import "leblanc.io/lotor/internal/token"

// TokenKind est la nature d'un jeton de l'API des agents (format : internal/token).
type TokenKind = token.Kind

// Natures de jetons de l'API des agents. Les jetons personnels (token.Personal) reviennent
// à l'API utilisateur (internal/account).
const (
	KindAgent      = token.Agent      // jeton d'agent : routes /api/v1/agent/* hors inscription
	KindEnrollment = token.Enrollment // jeton d'inscription d'un agent serveur
)

// SecretHash est le SHA-256 du secret d'un jeton.
type SecretHash = token.SecretHash

// IssuedToken est un jeton qui vient d'être tiré (secret montré une seule fois).
type IssuedToken = token.Issued

// ErrMalformedToken : la valeur présentée n'a pas le format d'un jeton de la nature
// attendue.
var ErrMalformedToken = token.ErrMalformed

// NewToken tire un jeton de la nature kind.
func NewToken(kind TokenKind) (IssuedToken, error) { return token.New(kind) }

// ParseToken lit un jeton de la nature kind (forme canonique seulement).
func ParseToken(kind TokenKind, s string) (string, SecretHash, error) { return token.Parse(kind, s) }

// KindOf renvoie la nature d'agent ou d'inscription annoncée par le préfixe d'un jeton,
// sans le valider ; un jeton personnel n'est pas un jeton de l'API des agents.
func KindOf(s string) (TokenKind, bool) { return token.KindOf(s, KindAgent, KindEnrollment) }

// DisplayPrefix est le début reconnaissable d'un jeton, sans rien de son secret.
func DisplayPrefix(kind TokenKind, publicID string) string {
	return token.DisplayPrefix(kind, publicID)
}
