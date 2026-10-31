package render

import (
	"fmt"
	"html"
	"html/template"

	"leblanc.io/open-go-base/i18n"
)

// CSRFFieldName est le champ de formulaire attendu par csrfx (sa valeur par défaut).
const CSRFFieldName = "csrf_token"

// staticFuncs ne dépendent ni de la langue ni de la requête.
func staticFuncs(assets *Assets) template.FuncMap {
	return template.FuncMap{
		"asset": assets.URL,
		"csrfField": func(token string) template.HTML {
			return template.HTML(`<input type="hidden" name="` + CSRFFieldName + `" value="` + html.EscapeString(token) + `">`)
		},
	}
}

// languageFuncs sont liées à une langue : chaque jeu de gabarits par langue les reçoit
// une fois, au démarrage (ADR 0009).
//
//	{{T "home.heading"}}
//	{{T "footer.version" "Version" .Page.Version}}   paires clé, valeur
//	{{T .Page.TitleKey .Page.TitleArgs}}             ou une table
//	{{Tn "projects.count" .Count}}
func languageFuncs(loc *i18n.Localizer) template.FuncMap {
	return template.FuncMap{
		"T": func(key string, args ...any) (string, error) {
			data, err := templateData(args)
			if err != nil {
				return "", fmt.Errorf("fonction T, clé %q : %w", key, err)
			}
			if data == nil {
				return loc.T(key), nil
			}
			return loc.T(key, data), nil
		},
		"Tn": func(key string, count int, args ...any) (string, error) {
			data, err := templateData(args)
			if err != nil {
				return "", fmt.Errorf("fonction Tn, clé %q : %w", key, err)
			}
			if data == nil {
				return loc.Tn(key, count), nil
			}
			data["Count"] = count
			return loc.Tn(key, count, data), nil
		},
	}
}

// placeholderFuncs déclarent les fonctions de langue à l'analyse des gabarits, avant que
// chaque jeu par langue ne reçoive les siennes.
func placeholderFuncs() template.FuncMap {
	return languageFuncs(nil)
}

// templateData accepte rien, une table (éventuellement nil) ou des paires clé, valeur.
func templateData(args []any) (map[string]any, error) {
	switch {
	case len(args) == 0:
		return nil, nil
	case len(args) == 1:
		switch m := args[0].(type) {
		case map[string]any:
			if len(m) == 0 {
				return nil, nil
			}
			out := make(map[string]any, len(m))
			for k, v := range m {
				out[k] = v
			}
			return out, nil
		case nil:
			return nil, nil
		}
		return nil, fmt.Errorf("argument %T : table ou paires clé, valeur attendues", args[0])
	case len(args)%2 != 0:
		return nil, fmt.Errorf("%d arguments : paires clé, valeur attendues", len(args))
	}
	out := make(map[string]any, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			return nil, fmt.Errorf("clé %v : texte attendu", args[i])
		}
		out[k] = args[i+1]
	}
	return out, nil
}
