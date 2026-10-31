package account

import (
	"crypto/rand"
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// Politique de mot de passe (décision du lot T03) : 12 caractères au moins, sans règle de
// composition, différent de l'e-mail. La borne haute évite de hacher des mégaoctets.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
	maxEmailLength    = 254
)

// ValidationError est une saisie refusée : Field nomme le champ, Key la clé de traduction
// du message (validation.*).
type ValidationError struct {
	Field string
	Key   string
}

func (e *ValidationError) Error() string { return "account: " + e.Field + " : " + e.Key }

// Clés de validation.
const (
	KeyEmailInvalid         = "validation.email_invalid"
	KeyPasswordTooShort     = "validation.password_too_short"
	KeyPasswordTooLong      = "validation.password_too_long"
	KeyPasswordIsEmail      = "validation.password_is_email"
	KeyPasswordUnchanged    = "validation.password_unchanged"
	KeyPasswordMismatch     = "validation.password_mismatch"
	KeyPasswordWrong        = "validation.password_wrong"
	KeyLanguageInvalid      = "validation.language_invalid"
	KeyThemeInvalid         = "validation.theme_invalid"
	KeyDefaultOrgInvalid    = "validation.default_org_invalid"
	KeyEmailTaken           = "validation.email_taken"
	KeyLastAdmin            = "validation.last_admin"
	KeyCannotTargetSelf     = "validation.cannot_target_self"
	KeyRescueTicketTooShort = "validation.rescue_ticket_too_short"
)

// IsValidation indique si err est une saisie refusée et renvoie sa clé.
func IsValidation(err error) (*ValidationError, bool) {
	var v *ValidationError
	ok := errors.As(err, &v)
	return v, ok
}

// NormalizeEmail met un e-mail sous la forme qu'utilise authx pour le retrouver (espaces
// retirés, minuscules) et vérifie qu'il s'agit d'une adresse nue.
func NormalizeEmail(email string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(email))
	if e == "" || len(e) > maxEmailLength {
		return "", &ValidationError{Field: "email", Key: KeyEmailInvalid}
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || addr.Name != "" {
		return "", &ValidationError{Field: "email", Key: KeyEmailInvalid}
	}
	return e, nil
}

// ValidatePassword applique la politique de mot de passe pour le compte email.
func ValidatePassword(password, email string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLength:
		return &ValidationError{Field: "password", Key: KeyPasswordTooShort}
	case n > MaxPasswordLength:
		return &ValidationError{Field: "password", Key: KeyPasswordTooLong}
	case email != "" && strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(email)):
		return &ValidationError{Field: "password", Key: KeyPasswordIsEmail}
	}
	return nil
}

// tempAlphabet exclut les caractères qui se confondent à la lecture (0/O, 1/l/I).
const tempAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"

// TempPasswordLength : 20 caractères parmi 54, soit environ 115 bits.
const TempPasswordLength = 20

// GeneratePassword produit un mot de passe temporaire, à changer à la première connexion.
func GeneratePassword() string {
	return randomFrom(tempAlphabet, TempPasswordLength)
}

func randomFrom(alphabet string, n int) string {
	out := make([]byte, n)
	// Tirage par rejet : pas de biais de modulo.
	limit := 256 - 256%len(alphabet)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		_, _ = rand.Read(buf) // ne renvoie jamais d'erreur : un échec interrompt le programme
		if int(buf[0]) >= limit {
			continue
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return string(out)
}
