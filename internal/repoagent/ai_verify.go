package repoagent

import (
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/package-url/packageurl-go"

	"leblanc.io/lotor/internal/sbom"
)

// Motifs de rejet d'un candidat par le vérificateur (comptés, puis journalisés).
const (
	RejectSchema         = "schema"
	RejectVersion        = "version_not_concrete"
	RejectFileMissing    = "file_missing"
	RejectFileExcluded   = "file_excluded"
	RejectLine           = "line_out_of_range"
	RejectExcerpt        = "excerpt_not_found"
	RejectName           = "name_absent"
	RejectVersionAbsent  = "version_absent"
	RejectPURLInvalid    = "purl_invalid"
	RejectPURLMismatch   = "purl_mismatch"
	RejectTypeIncoherent = "type_incoherent"
	RejectDuplicate      = "duplicate"
	RejectDocumentation  = "evidence_in_documentation"
	RejectPURLExcerpt    = "excerpt_is_purl"
	RejectSuspicious     = "suspicious_file"
	RejectManifest       = "evidence_in_manifest"
)

// lineTolerance est l'écart toléré entre la ligne annoncée et la ligne de l'extrait.
const lineTolerance = 3

// Accepted est un composant IA dont la preuve a été vérifiée.
type Accepted struct {
	Candidate
	// PURL est le purl canonique (sbom.CanonicalPURL).
	PURL sbom.PURL
	// Line est la ligne où l'extrait a été retrouvé (peut différer de la ligne annoncée
	// dans la tolérance).
	Line int
	// index est le rang du candidat dans la liste jugée.
	index int
}

// Verdict est le résultat du vérificateur.
type Verdict struct {
	Accepted []Accepted
	// Rejected compte les candidats rejetés par motif.
	Rejected map[string]int
}

func (v *Verdict) reject(reason string) {
	if v.Rejected == nil {
		v.Rejected = map[string]int{}
	}
	v.Rejected[reason]++
}

// RejectedCount renvoie le nombre total de candidats rejetés.
func (v Verdict) RejectedCount() int {
	n := 0
	for _, c := range v.Rejected {
		n += c
	}
	return n
}

// knownPURLTypes sont les types purl acceptés pour un composant IA.
var knownPURLTypes = []string{
	"apk", "bitbucket", "cargo", "cocoapods", "composer", "conan", "conda", "cran", "deb", "docker", "gem",
	"generic", "github", "golang", "hackage", "hex", "maven", "npm", "nuget", "oci", "pub", "pypi", "rpm", "swift",
}

// nonVersions ne sont jamais des versions.
var nonVersions = []string{"latest", "stable", "master", "main", "head", "dev", "edge", "nightly", "next", "current", "release", "lts"}

// verify juge les candidats, seul et de façon déterministe : il relit chaque fichier dans
// l'arborescence de l'analyse (le commit analysé), retrouve l'extrait à la ligne annoncée
// (à lineTolerance lignes près), y exige le nom et la version, vérifie le purl et sa
// cohérence avec le fichier. Tout échec rejette le candidat et compte son motif ; un
// candidat n'est jamais corrigé.
func verify(ws *workspace, cands []Candidate) Verdict {
	var v Verdict
	seen := map[string]bool{}
	for i, c := range cands {
		a, reason := verifyOne(ws, c)
		a.index = i
		if reason != "" {
			v.reject(reason)
			continue
		}
		if seen[a.PURL.String] {
			v.reject(RejectDuplicate)
			continue
		}
		seen[a.PURL.String] = true
		v.Accepted = append(v.Accepted, a)
	}
	return v
}

func verifyOne(ws *workspace, c Candidate) (Accepted, string) {
	c.Name, c.Version, c.File = strings.TrimSpace(c.Name), strings.TrimSpace(c.Version), strings.TrimSpace(c.File)
	if c.Name == "" || c.Version == "" || c.File == "" || c.Line < 1 || c.Confidence < 0 || c.Confidence > 1 ||
		len(c.Name) > 214 || len(c.Version) > 128 || len(c.Excerpt) > 500 {
		return Accepted{}, RejectSchema
	}
	if !concreteVersion(c.Version) {
		return Accepted{}, RejectVersion
	}
	rel, err := ws.clean(c.File)
	if err != nil || rel == "." {
		return Accepted{}, RejectFileMissing
	}
	if ws.excl.match(rel) {
		return Accepted{}, RejectFileExcluded
	}
	if documentation(rel) {
		return Accepted{}, RejectDocumentation
	}
	if manifest(rel) {
		return Accepted{}, RejectManifest
	}
	content, err := ws.content(rel)
	switch {
	case errors.Is(err, errExcluded):
		return Accepted{}, RejectFileExcluded
	case err != nil:
		return Accepted{}, RejectFileMissing
	}
	if injectionMarker.Match(content) {
		return Accepted{}, RejectSuspicious
	}
	lines := splitLines(content)
	if c.Line > len(lines) {
		return Accepted{}, RejectLine
	}
	ex := normalizeSpace(c.Excerpt)
	if len([]rune(strings.ReplaceAll(ex, " ", ""))) < 3 {
		return Accepted{}, RejectExcerpt
	}
	if purlLiteral.MatchString(ex) {
		return Accepted{}, RejectPURLExcerpt
	}
	found := excerptLine(lines, c.Line, ex)
	if found == 0 {
		return Accepted{}, RejectExcerpt
	}
	if !containsVersion(ex, c.Version) {
		return Accepted{}, RejectVersionAbsent
	}
	lo, hi := max(found-lineTolerance, 1), min(found+lineTolerance, len(lines))
	window := strings.Join(lines[lo-1:hi], "\n")
	if len(window) > maxVerifyWindow {
		window = ex
	}
	if !containsName(window, c.Name) {
		return Accepted{}, RejectName
	}
	p, reason := checkPURL(c)
	if reason != "" {
		return Accepted{}, reason
	}
	if !coherent(p.Type, rel) {
		return Accepted{}, RejectTypeIncoherent
	}
	c.File = rel
	return Accepted{Candidate: c, PURL: p, Line: found}, ""
}

// docExt et docNames désignent la documentation : une version citée en prose (README,
// journal des modifications, guide) n'est pas la preuve d'un composant livré, et c'est le
// terrain d'élection d'une instruction malveillante.
var (
	docExt   = []string{".md", ".markdown", ".mdx", ".rst", ".adoc", ".asciidoc", ".org", ".rdoc"}
	docNames = []string{"readme", "changelog", "changes", "history", "news", "license", "licence", "copying", "notice",
		"authors", "contributing", "security", "code_of_conduct", "releasenotes", "release-notes"}
)

func documentation(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if slices.Contains(docExt, path.Ext(base)) {
		return true
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	return slices.Contains(docNames, stem)
}

// manifestNames sont les manifestes et fichiers de verrouillage que Syft lit : un
// composant qui s'y trouve est déjà dans l'inventaire de Syft, qui l'emporte.
var manifestNames = []string{
	"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
	"go.mod", "go.sum", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg", "uv.lock",
	"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock",
	"composer.json", "composer.lock", "packages.config", "packages.lock.json", "mix.exs", "mix.lock", "pubspec.yaml",
	"pubspec.lock", "podfile.lock", "package.resolved", "conanfile.txt", "conan.lock", "vcpkg.json", "rebar.lock",
	"stack.yaml.lock", "cabal.project.freeze",
}

func manifest(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if slices.Contains(manifestNames, base) {
		return true
	}
	ext := path.Ext(base)
	return ext == ".gemspec" || ext == ".csproj" || ext == ".nuspec" ||
		(strings.HasPrefix(base, "requirements") && ext == ".txt")
}

// purlLiteral repère un purl écrit dans l'extrait : un fichier qui cite un purl parle d'un
// composant, il ne le contient pas (forme typique d'une instruction injectée).
var purlLiteral = regexp.MustCompile(`(?i)\bpkg:[a-z][a-z0-9.+-]*/`)

// injectionMarker repère un fichier qui s'adresse à un modèle ou à un outil d'analyse
// (injection d'instructions) : aucune preuve n'en est acceptée. Liste volontairement
// étroite, mesurée sur le corpus (testdata/ai-corpus) ; un faux négatif reste soumis aux
// autres contrôles.
var injectionMarker = regexp.MustCompile(`(?i)ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions` +
	`|(?:message|note|notice|instructions?)\s+(?:to|for)\s+(?:any\s+|all\s+)?(?:ai|llms?|language\s+models?|automated\s+(?:analysis|tools?)|assistants?|bots?)\b` +
	`|\byou\s+are\s+now\b|\bsystem\s+prompt\b|\bsubmit_candidates\b|\b(?:read_file|list_dir)\b`)

// concreteVersion refuse une plage, un joker, une étiquette mouvante ou une version qui
// ne contient aucun chiffre.
func concreteVersion(v string) bool {
	lv := strings.ToLower(v)
	if slices.Contains(nonVersions, lv) || !strings.ContainsFunc(v, unicode.IsDigit) {
		return false
	}
	if strings.ContainsAny(v, " \t*^~<>=|,") || strings.HasSuffix(lv, ".x") || strings.Contains(lv, ".x.") {
		return false
	}
	return true
}

var spaces = regexp.MustCompile(`\s+`)

func normalizeSpace(s string) string { return strings.TrimSpace(spaces.ReplaceAllString(s, " ")) }

// excerptLine renvoie la ligne (1-based) où commence l'extrait, cherchée de la ligne
// annoncée vers l'extérieur dans la tolérance ; 0 s'il n'y est pas. Un extrait peut
// couvrir plusieurs lignes consécutives.
func excerptLine(lines []string, line int, ex string) int {
	order := []int{line}
	for d := 1; d <= lineTolerance; d++ {
		order = append(order, line-d, line+d)
	}
	for _, n := range order {
		if n < 1 || n > len(lines) {
			continue
		}
		first := normalizeSpace(lines[n-1])
		end := min(n+lineTolerance, len(lines))
		joined := normalizeSpace(strings.Join(lines[n-1:end], "\n"))
		if i := strings.Index(joined, ex); i >= 0 && i < len(first) {
			return n
		}
	}
	return 0
}

// containsVersion exige la version comme élément entier : précédée et suivie d'un
// caractère qui ne prolonge pas un numéro (« 1.2 » n'est pas dans « 11.2.3 »). Un « v »
// en tête est toléré des deux côtés.
func containsVersion(text, version string) bool {
	v := strings.TrimPrefix(strings.ToLower(version), "v")
	re := regexp.MustCompile(`(^|[^0-9A-Za-z.])v?` + regexp.QuoteMeta(v) + `($|[^0-9A-Za-z.]|\.(?:$|[^0-9A-Za-z]))`)
	return re.MatchString(strings.ToLower(text))
}

// nameVariants renvoie les formes du nom à chercher : le nom entier, et sa dernière
// partie après « / » (espace de noms npm, image docker library/nginx…).
func nameVariants(name string) []string {
	out := []string{name}
	if i := strings.LastIndex(name, "/"); i >= 0 && i < len(name)-1 {
		out = append(out, name[i+1:])
	}
	return out
}

// containsName exige le nom comme mot entier, sans tenir compte de la casse, « - », « _ »,
// « . » et espace étant interchangeables.
func containsName(text, name string) bool {
	lower := strings.ToLower(text)
	for _, n := range nameVariants(strings.ToLower(name)) {
		var b strings.Builder
		b.WriteString(`(^|[^a-z0-9])`)
		for _, r := range n {
			if strings.ContainsRune("-_. ", r) {
				b.WriteString(`[-_. ]`)
				continue
			}
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
		b.WriteString(`($|[^a-z0-9])`)
		if regexp.MustCompile(b.String()).MatchString(lower) {
			return true
		}
	}
	return false
}

// sameName compare deux noms sans tenir compte de la casse ni des séparateurs.
func sameName(a, b string) bool {
	norm := func(s string) string {
		return strings.Map(func(r rune) rune {
			if strings.ContainsRune("-_. ", r) {
				return -1
			}
			return unicode.ToLower(r)
		}, s)
	}
	return norm(a) == norm(b)
}

// checkPURL vérifie que le purl est valide, d'un type connu, au même nom et à la même
// version que le candidat.
func checkPURL(c Candidate) (sbom.PURL, string) {
	p, err := sbom.CanonicalPURL(strings.TrimSpace(c.PURL))
	if err != nil {
		return sbom.PURL{}, RejectPURLInvalid
	}
	raw, err := packageurl.FromString(strings.TrimSpace(c.PURL))
	if err != nil || !slices.Contains(knownPURLTypes, p.Type) || p.Version == "" {
		return sbom.PURL{}, RejectPURLInvalid
	}
	if strings.TrimPrefix(strings.ToLower(p.Version), "v") != strings.TrimPrefix(strings.ToLower(c.Version), "v") {
		return sbom.PURL{}, RejectPURLMismatch
	}
	full := raw.Name
	if raw.Namespace != "" {
		full = raw.Namespace + "/" + raw.Name
	}
	ok := false
	for _, n := range nameVariants(c.Name) {
		if sameName(n, raw.Name) || sameName(n, full) {
			ok = true
		}
	}
	if !ok {
		return sbom.PURL{}, RejectPURLMismatch
	}
	return p, ""
}

// coherent vérifie que le type purl va avec le fichier de la preuve : une image de
// conteneur se lit dans un Dockerfile, un fichier Compose ou un manifeste YAML ; une
// bibliothèque recopiée en JavaScript ou CSS est un paquet npm, une version GitHub ou un
// composant générique.
func coherent(purlType, rel string) bool {
	base := strings.ToLower(path.Base(rel))
	ext := path.Ext(base)
	switch purlType {
	case "docker", "oci":
		return strings.HasPrefix(base, "dockerfile") || strings.HasPrefix(base, "containerfile") ||
			strings.HasSuffix(base, ".dockerfile") || strings.HasSuffix(base, ".containerfile") ||
			ext == ".yml" || ext == ".yaml" || ext == ".hcl" || ext == ".tf" || ext == ".nomad" || base == "makefile" ||
			ext == ".sh" || ext == ".json"
	}
	switch ext {
	case ".js", ".mjs", ".cjs", ".css", ".scss", ".less", ".map":
		return purlType == "npm" || purlType == "github" || purlType == "generic"
	}
	return true
}
