package pagination

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// version préfixe les curseurs : un changement de format les invalide proprement.
const version = "1."

// MaxCursorLen borne un curseur reçu.
const MaxCursorLen = 1024

// ErrInvalidCursor : curseur illisible, trop long ou d'un autre format.
var ErrInvalidCursor = errors.New("pagination: curseur invalide")

// LimitError : taille de page hors bornes.
type LimitError struct{ Max int }

func (e *LimitError) Error() string {
	return fmt.Sprintf("pagination: taille de page hors de [1, %d]", e.Max)
}

// Limit renvoie la taille de page demandée, def si elle est absente, et une *LimitError
// si elle sort de [1, max].
func Limit(requested *int, def, max int) (int, error) {
	if requested == nil {
		return def, nil
	}
	if *requested < 1 || *requested > max {
		return 0, &LimitError{Max: max}
	}
	return *requested, nil
}

// Encode produit un curseur opaque à partir d'une clé de tri sérialisable en JSON.
func Encode(key any) (string, error) {
	body, err := json.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("pagination: encodage du curseur : %w", err)
	}
	return version + base64.RawURLEncoding.EncodeToString(body), nil
}

// Decode relit un curseur produit par Encode dans key. Un champ inconnu est refusé : un
// curseur d'une autre liste ne s'applique pas en silence.
func Decode(cursor string, key any) error {
	if len(cursor) > MaxCursorLen {
		return ErrInvalidCursor
	}
	payload, ok := strings.CutPrefix(cursor, version)
	if !ok {
		return ErrInvalidCursor
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return ErrInvalidCursor
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(key); err != nil || dec.More() {
		return ErrInvalidCursor
	}
	return nil
}

// Page est une page de résultats et le curseur de la suivante (vide s'il n'y en a pas).
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// Build construit une page à partir de lignes lues avec LIMIT limit+1 : la ligne en trop
// signale une page suivante, dont le curseur est la clé du dernier élément rendu.
func Build[T any](rows []T, limit int, key func(T) any) (Page[T], error) {
	if len(rows) <= limit {
		return Page[T]{Items: rows}, nil
	}
	items := rows[:limit]
	next, err := Encode(key(items[len(items)-1]))
	if err != nil {
		return Page[T]{}, err
	}
	return Page[T]{Items: items, NextCursor: next}, nil
}
