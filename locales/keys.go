package locales

import (
	"fmt"
	"io/fs"
	"maps"
	"slices"

	"gopkg.in/yaml.v3"
)

// Reference est la langue de référence : toute autre langue a exactement ses clés.
const Reference = "fr"

// pluralMarker remplace la valeur d'un message pluriel dans Messages.
const pluralMarker = "(plural)"

// Keys renvoie les clés de la langue de référence, triées, un message pluriel comptant
// pour une clé. Les tests d'usage (gabarits, clés d'erreur) s'en servent.
func Keys() ([]string, error) {
	msgs, err := Messages(Reference)
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(msgs)), nil
}

// Messages renvoie les messages d'une langue, clés aplaties (home.heading). Un message
// pluriel (table de catégories CLDR) vaut une seule entrée.
func Messages(lang string) (map[string]string, error) {
	body, err := fs.ReadFile(FS, lang+".yaml")
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := yaml.Unmarshal(body, &tree); err != nil {
		return nil, fmt.Errorf("%s.yaml : %w", lang, err)
	}
	out := map[string]string{}
	if err := flatten("", tree, out); err != nil {
		return nil, fmt.Errorf("%s.yaml : %w", lang, err)
	}
	return out, nil
}

func flatten(prefix string, node map[string]any, out map[string]string) error {
	for k, v := range node {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch v := v.(type) {
		case string:
			out[key] = v
		case map[string]any:
			if isPlural(v) {
				out[key] = pluralMarker
				continue
			}
			if err := flatten(key, v, out); err != nil {
				return err
			}
		default:
			return fmt.Errorf("clé %s : valeur de type %T, texte attendu", key, v)
		}
	}
	return nil
}

func isPlural(m map[string]any) bool {
	for k := range m {
		switch k {
		case "zero", "one", "two", "few", "many", "other":
		default:
			return false
		}
	}
	return len(m) > 0
}
