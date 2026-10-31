// Package version compare les versions par écosystème et lit les plages vers (ADR 0026).
//
// La comparaison passe par l'interface Comparer, dont l'adaptateur grypeversion fournit
// l'implémentation (comparateurs de Grype : node-semver, Maven, PEP 440, RubyGems, modules
// Go, dpkg, rpm, apk, semver générique) ; le reste du serveur ne connaît pas Grype. La
// règle d'un composant vient du type de son purl (ForPURLType).
//
// Les plages suivent la spécification vers (purl VERSION-RANGE-SPEC), lues par un
// analyseur propre au projet : ParseVers vérifie la forme, le schéma, la lisibilité et
// l'unicité des versions, et trie les contraintes ; Range.Contains applique l'algorithme
// de la spécification. Une version illisible dans son schéma renvoie ErrNotComparable,
// jamais un résultat silencieux.
//
//	r, err := version.ParseVers("vers:npm/>=4.0.0|<4.17.21", cmp)
//	in, err := r.Contains(cmp, "4.17.20") // vrai
//	sorted, unreadable := version.Sort(cmp, version.ForPURLType("maven"), versions)
package version
