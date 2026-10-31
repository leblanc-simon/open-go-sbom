package config

import (
	"reflect"
	"strings"
)

// Field décrit une feuille de la configuration : son chemin YAML et sa variable
// d'environnement.
type Field struct {
	Path        string // database.driver
	Env         string // OGSBOM_DB_DRIVER
	Description string
}

// Fields énumère les feuilles de Config, dans l'ordre de déclaration. Les tests s'en
// servent pour vérifier que --help et config.example.yaml couvrent tout.
func Fields() []Field {
	var out []Field
	walk(reflect.TypeFor[Config](), "", "", &out)
	return out
}

func walk(t reflect.Type, path, prefix string, out *[]Field) {
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		p := path
		if name != "" {
			p = join(path, name)
		}
		pre := prefix + f.Tag.Get("env-prefix")
		if f.Type.Kind() == reflect.Struct && f.Type.String() != "time.Duration" && f.Tag.Get("env") == "" {
			walk(f.Type, p, pre, out)
			continue
		}
		*out = append(*out, Field{Path: p, Env: pre + f.Tag.Get("env"), Description: f.Tag.Get("env-description")})
	}
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

// envOf renvoie la variable d'environnement d'un chemin YAML.
func envOf(path string) string {
	for _, f := range Fields() {
		if f.Path == path {
			return f.Env
		}
	}
	return ""
}
