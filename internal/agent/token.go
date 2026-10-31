package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"io"
	"strings"
)

// TokenKind est la nature d'un jeton, lisible dans son préfixe (§ 10 de l'architecture).
type TokenKind string

// Natures de jetons de ce paquet. Le préfixe ogsbom_pat_ des jetons personnels revient à
// l'API utilisateur.
const (
	KindAgent      TokenKind = "agt" // jeton d'agent : routes /api/v1/agent/* hors inscription
	KindEnrollment TokenKind = "enr" // jeton d'inscription d'un agent serveur
)

// Format d'un jeton : ogsbom_<nature>_<identifiant public>_<secret>. L'identifiant public
// (128 bits) désigne la ligne et son organisation ; le secret (256 bits) n'est jamais
// stocké, seulement son SHA-256. Les deux parties sont en base32 minuscule sans
// remplissage : ni « _ » ni « - », donc un découpage sans ambiguïté et un jeton qu'un
// double-clic sélectionne en entier.
const (
	tokenPrefix  = "ogsbom_"
	publicBytes  = 16
	secretBytes  = 32
	publicIDLen  = 26 // base32 de 16 octets
	secretLen    = 52 // base32 de 32 octets
	tokenBodyLen = publicIDLen + 1 + secretLen
	// displayLen est le nombre de caractères de l'identifiant public affichés pour
	// reconnaître un jeton (« ogsbom_agt_k7q2xa… »).
	displayLen = 6
)

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrMalformedToken : la valeur présentée n'a pas le format d'un jeton de la nature
// attendue. Aucune requête en base n'est faite pour elle.
var ErrMalformedToken = errors.New("agent: jeton mal formé")

// SecretHash est le SHA-256 du secret d'un jeton.
type SecretHash [sha256.Size]byte

// Matches compare deux empreintes en temps constant.
func (h SecretHash) Matches(stored []byte) bool {
	return len(stored) == sha256.Size && subtle.ConstantTimeCompare(h[:], stored) == 1
}

// IssuedToken est un jeton qui vient d'être tiré : Plaintext n'est montré qu'une fois et
// jamais stocké ni journalisé.
type IssuedToken struct {
	Kind      TokenKind
	PublicID  string
	Hash      SecretHash
	Plaintext string
}

// issueToken tire un jeton de la nature kind depuis rnd (crypto/rand hors tests).
func issueToken(kind TokenKind, rnd io.Reader) (IssuedToken, error) {
	buf := make([]byte, publicBytes+secretBytes)
	if _, err := io.ReadFull(rnd, buf); err != nil {
		return IssuedToken{}, errors.Join(errors.New("agent: tirage d'un jeton"), err)
	}
	pub, sec := buf[:publicBytes], buf[publicBytes:]
	t := IssuedToken{Kind: kind, PublicID: b32.EncodeToString(pub), Hash: sha256.Sum256(sec)}
	t.Plaintext = tokenPrefix + string(kind) + "_" + t.PublicID + "_" + b32.EncodeToString(sec)
	return t, nil
}

// NewToken tire un jeton de la nature kind.
func NewToken(kind TokenKind) (IssuedToken, error) { return issueToken(kind, rand.Reader) }

// ParseToken lit un jeton de la nature kind et renvoie son identifiant public et
// l'empreinte de son secret. Seule la forme canonique est acceptée.
func ParseToken(kind TokenKind, s string) (publicID string, hash SecretHash, err error) {
	body, ok := strings.CutPrefix(s, tokenPrefix+string(kind)+"_")
	if !ok || len(body) != tokenBodyLen || body[publicIDLen] != '_' {
		return "", SecretHash{}, ErrMalformedToken
	}
	publicID, secretPart := body[:publicIDLen], body[publicIDLen+1:]
	pub, err := b32.DecodeString(publicID)
	if err != nil || len(pub) != publicBytes || b32.EncodeToString(pub) != publicID {
		return "", SecretHash{}, ErrMalformedToken
	}
	sec, err := b32.DecodeString(secretPart)
	if err != nil || len(sec) != secretBytes || b32.EncodeToString(sec) != secretPart {
		return "", SecretHash{}, ErrMalformedToken
	}
	return publicID, sha256.Sum256(sec), nil
}

// KindOf renvoie la nature annoncée par le préfixe d'un jeton, sans le valider.
func KindOf(s string) (TokenKind, bool) {
	for _, k := range []TokenKind{KindAgent, KindEnrollment} {
		if strings.HasPrefix(s, tokenPrefix+string(k)+"_") {
			return k, true
		}
	}
	return "", false
}

// DisplayPrefix est le début reconnaissable d'un jeton, sans rien de son secret.
func DisplayPrefix(kind TokenKind, publicID string) string {
	if len(publicID) > displayLen {
		publicID = publicID[:displayLen]
	}
	return tokenPrefix + string(kind) + "_" + publicID
}
