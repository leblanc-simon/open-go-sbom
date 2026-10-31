package forge

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ParseRSAPrivateKey lit une clé privée RSA au format PEM, PKCS #1 (format téléchargé
// depuis GitHub) ou PKCS #8.
func ParseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("forge: clé privée : bloc PEM introuvable")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("forge: clé privée PKCS #1 illisible : %w", err)
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("forge: clé privée PKCS #8 illisible : %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("forge: clé privée : RSA attendue")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("forge: clé privée : bloc PEM %q inattendu", block.Type)
	}
}

// Durées du JWT d'une GitHub App : GitHub refuse une expiration à plus de 10 minutes ;
// l'émission est antidatée d'une minute pour tolérer un léger décalage d'horloge.
const (
	jwtBackdate = time.Minute
	jwtLifetime = 9 * time.Minute
)

// appJWT signe le JWT RS256 d'une GitHub App, qui authentifie l'application elle-même
// (et non une installation) auprès de l'API.
func appJWT(key *rsa.PrivateKey, issuer string, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{now.Add(-jwtBackdate).Unix(), now.Add(jwtLifetime).Unix(), issuer})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("forge: signature du JWT : %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
