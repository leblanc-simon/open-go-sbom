package vuln

import "strings"

// Metric est une métrique de base d'un vecteur CVSS 3.x : son nom (AV, AC…) et sa
// valeur (N, L…), en minuscules pour former des clés de traduction.
type Metric struct {
	Name  string
	Value string
}

// cvss3Base liste les métriques de base de CVSS 3.0 et 3.1, dans l'ordre de la
// spécification, avec leurs valeurs admises.
var cvss3Base = []struct {
	name   string
	values string
}{
	{"AV", "NALP"}, {"AC", "LH"}, {"PR", "NLH"}, {"UI", "NR"}, {"S", "UC"}, {"C", "NLH"}, {"I", "NLH"}, {"A", "NLH"},
}

// ParseCVSS3 lit les métriques de base d'un vecteur CVSS 3.x
// (« CVSS:3.1/AV:N/AC:L/… »). Un vecteur d'une autre version, incomplet ou mal formé
// donne nil : l'écran n'affiche alors que le vecteur brut.
func ParseCVSS3(vector string) []Metric {
	parts := strings.Split(vector, "/")
	if len(parts) < 1+len(cvss3Base) || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return nil
	}
	seen := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok || len(v) != 1 {
			return nil
		}
		if _, dup := seen[k]; dup {
			return nil
		}
		seen[k] = v
	}
	out := make([]Metric, 0, len(cvss3Base))
	for _, m := range cvss3Base {
		v, ok := seen[m.name]
		if !ok || !strings.Contains(m.values, v) {
			return nil
		}
		out = append(out, Metric{Name: strings.ToLower(m.name), Value: strings.ToLower(v)})
	}
	return out
}
