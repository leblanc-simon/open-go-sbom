package benchdata

import (
	"encoding/json"
	"fmt"
)

// knownVulnerable sont de vrais paquets vulnérables, pour que la correspondance du SBOM
// synthétique produise des constats et parcoure les fiches de la base.
var knownVulnerable = []struct{ purl, name, version string }{
	{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j-core", "2.14.1"},
	{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10", "jackson-databind", "2.9.10"},
	{"pkg:maven/org.springframework/spring-core@5.3.17", "spring-core", "5.3.17"},
	{"pkg:maven/org.apache.commons/commons-text@1.9", "commons-text", "1.9"},
	{"pkg:npm/lodash@4.17.15", "lodash", "4.17.15"},
	{"pkg:npm/minimist@1.2.0", "minimist", "1.2.0"},
	{"pkg:npm/axios@0.21.0", "axios", "0.21.0"},
	{"pkg:pypi/django@2.2.0", "django", "2.2.0"},
	{"pkg:pypi/requests@2.19.0", "requests", "2.19.0"},
	{"pkg:pypi/urllib3@1.24.1", "urllib3", "1.24.1"},
}

// SyntheticCycloneDX construit un SBOM CycloneDX 1.6 de n composants : les paquets
// vulnérables connus, puis des paquets synthétiques npm, maven, pypi et golang
// (proportions 50, 30, 18 et 2 %). variant change la version du premier paquet
// synthétique : deux variantes donnent deux inventaires distincts.
func SyntheticCycloneDX(n, variant int) ([]byte, error) {
	type component struct {
		BOMRef  string `json:"bom-ref"`
		Type    string `json:"type"`
		Group   string `json:"group,omitempty"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	}
	cs := make([]component, 0, n)
	for _, k := range knownVulnerable {
		if len(cs) == n {
			break
		}
		cs = append(cs, component{BOMRef: k.purl, Type: "library", Name: k.name, Version: k.version, PURL: k.purl})
	}
	for i := 0; len(cs) < n; i++ {
		v := fmt.Sprintf("1.%d.%d", i%13, i%7)
		if i == 0 {
			v = fmt.Sprintf("0.0.%d", variant)
		}
		var c component
		switch r := i % 50; {
		case r < 25:
			c = component{Name: fmt.Sprintf("bench-pkg-%d", i), PURL: fmt.Sprintf("pkg:npm/bench-pkg-%d@%s", i, v)}
		case r < 40:
			c = component{Group: "org.bench", Name: fmt.Sprintf("lib-%d", i), PURL: fmt.Sprintf("pkg:maven/org.bench/lib-%d@%s", i, v)}
		case r < 49:
			c = component{Name: fmt.Sprintf("bench-py-%d", i), PURL: fmt.Sprintf("pkg:pypi/bench-py-%d@%s", i, v)}
		default:
			c = component{Name: fmt.Sprintf("example.org/bench/mod%d", i), PURL: fmt.Sprintf("pkg:golang/example.org/bench/mod%d@v%s", i, v)}
			v = "v" + v
		}
		c.BOMRef, c.Type, c.Version = c.PURL, "library", v
		cs = append(cs, c)
	}
	return json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"serialNumber": fmt.Sprintf("urn:uuid:00000000-0000-4000-8000-%012d", variant),
		"metadata":     map[string]any{"timestamp": "2026-10-31T00:00:00Z", "component": map[string]any{"bom-ref": "bench", "type": "application", "name": "bench", "version": "1.0.0"}},
		"components":   cs,
	})
}
