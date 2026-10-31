package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	formatV1  byte = 1
	keySize        = 32
	nonceSize      = 12
	aadPrefix      = "lotor-secret-v1"
)

var (
	// ErrUnknownKey : le chiffré désigne une clé absente de la configuration.
	ErrUnknownKey = errors.New("secret: clé inconnue")
	// ErrInvalidCiphertext : chiffré tronqué, altéré, ou lié à d'autres données.
	ErrInvalidCiphertext = errors.New("secret: chiffré invalide")
)

var keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Box chiffre et déchiffre avec un jeu de clés versionnées. Sûr en concurrence.
type Box struct {
	active string
	aeads  map[string]cipher.AEAD
}

// New construit un Box à partir de clés brutes de 32 octets.
func New(keys map[string][]byte, active string) (*Box, error) {
	if len(keys) == 0 {
		return nil, errors.New("secret: aucune clé")
	}
	b := &Box{active: active, aeads: make(map[string]cipher.AEAD, len(keys))}
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("secret: nom de clé %q invalide (minuscules, chiffres, - et _, 32 caractères au plus)", id)
		}
		if len(key) != keySize {
			return nil, fmt.Errorf("secret: la clé %q fait %d octets, 32 attendus", id, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("secret: clé %q : %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secret: clé %q : %w", id, err)
		}
		b.aeads[id] = aead
	}
	if _, ok := b.aeads[active]; !ok {
		return nil, fmt.Errorf("secret: la clé active %q n'est pas définie", active)
	}
	return b, nil
}

// Parse construit un Box à partir de clés encodées en base64 (standard ou URL, avec ou
// sans remplissage), telles qu'elles figurent en configuration.
func Parse(encoded map[string]string, active string) (*Box, error) {
	keys := make(map[string][]byte, len(encoded))
	for id, s := range encoded {
		key, err := decodeKey(s)
		if err != nil {
			return nil, fmt.Errorf("secret: la clé %q n'est pas en base64", id)
		}
		keys[id] = key
	}
	return New(keys, active)
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(s); err == nil {
			return key, nil
		}
	}
	return nil, errors.New("base64 invalide")
}

// ActiveKeyID renvoie le nom de la clé qui chiffre.
func (b *Box) ActiveKeyID() string { return b.active }

// KeyIDs renvoie les noms des clés connues, triés.
func (b *Box) KeyIDs() []string {
	ids := make([]string, 0, len(b.aeads))
	for id := range b.aeads {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Seal chiffre plaintext avec la clé active. aad lie le chiffré à son contexte (par
// exemple la table et l'identifiant de la ligne) ; il faudra le même pour déchiffrer.
func (b *Box) Seal(plaintext, aad []byte) (ciphertext []byte, keyID string, err error) {
	aead := b.aeads[b.active]
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("secret: aléa : %w", err)
	}
	out := make([]byte, 0, 1+nonceSize+len(plaintext)+aead.Overhead())
	out = append(out, formatV1)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, additionalData(b.active, aad))
	return out, b.active, nil
}

// Open déchiffre un chiffré produit par Seal avec la clé keyID.
func (b *Box) Open(ciphertext []byte, keyID string, aad []byte) ([]byte, error) {
	aead, ok := b.aeads[keyID]
	if !ok {
		return nil, fmt.Errorf("%w : %q", ErrUnknownKey, keyID)
	}
	if len(ciphertext) < 1+nonceSize+aead.Overhead() || ciphertext[0] != formatV1 {
		return nil, ErrInvalidCiphertext
	}
	nonce := ciphertext[1 : 1+nonceSize]
	plaintext, err := aead.Open(nil, nonce, ciphertext[1+nonceSize:], additionalData(keyID, aad))
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

// NeedsRotation indique si un chiffré de la clé keyID doit être rechiffré.
func (b *Box) NeedsRotation(keyID string) bool { return keyID != b.active }

// Rotate rechiffre avec la clé active un chiffré produit par une autre clé.
func (b *Box) Rotate(ciphertext []byte, keyID string, aad []byte) ([]byte, string, error) {
	plaintext, err := b.Open(ciphertext, keyID, aad)
	if err != nil {
		return nil, "", err
	}
	return b.Seal(plaintext, aad)
}

func additionalData(keyID string, aad []byte) []byte {
	out := make([]byte, 0, len(aadPrefix)+len(keyID)+len(aad)+2)
	out = append(out, aadPrefix...)
	out = append(out, 0)
	out = append(out, keyID...)
	out = append(out, 0)
	return append(out, aad...)
}
