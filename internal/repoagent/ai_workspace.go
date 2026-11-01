package repoagent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// DefaultExclude est la liste des motifs de fichiers jamais montrés au modèle : secrets,
// clés, fichiers d'environnement et d'identifiants. Un motif sans « / » s'applique au nom
// de chaque élément du chemin (un répertoire « .ssh » masque tout son contenu) ; un motif
// avec « / » s'applique au chemin entier (syntaxe de path.Match).
var DefaultExclude = []string{
	".env", ".env.*", "*.env", ".envrc",
	"*.pem", "*.key", "*.crt", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.p8", "*.ppk", "*.asc", "*.gpg",
	"id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
	".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
	".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".gitconfig",
	".htpasswd", "credentials", "credentials.*", "secrets", "secrets.*", "*.secret", "*.secrets",
	"*.tfstate", "*.tfstate.*", "*.tfvars", "*.kdbx", "*.sqlite", "*.db",
	"service-account*.json", "*serviceaccount*.json", "kubeconfig*",
}

// privateKeyMarkers repèrent une clé privée dans un contenu, quel que soit le nom du
// fichier : un tel fichier est traité comme exclu.
var privateKeyMarkers = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	regexp.MustCompile(`PuTTY-User-Key-File-\d`),
}

// Erreurs du répertoire d'analyse.
var (
	errExcluded   = errors.New("file excluded from analysis")
	errNotText    = errors.New("not a text file")
	errBadPath    = errors.New("invalid path: relative path inside the repository expected")
	errReadBudget = errors.New("read budget exhausted")
)

// exclusions applique les motifs d'exclusion.
type exclusions struct {
	names []string // motifs sans « / »
	paths []string // motifs avec « / »
}

func newExclusions(patterns []string) (exclusions, error) {
	var e exclusions
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil || p == "" {
			return e, fmt.Errorf("motif d'exclusion %q invalide", p)
		}
		if strings.Contains(p, "/") {
			e.paths = append(e.paths, strings.TrimPrefix(p, "/"))
		} else {
			e.names = append(e.names, p)
		}
	}
	return e, nil
}

// match indique si le chemin relatif rel (séparateurs « / ») est exclu.
func (e exclusions) match(rel string) bool {
	if rel == "." || rel == "" {
		return false
	}
	lower := strings.ToLower(rel)
	for _, p := range e.paths {
		if ok, _ := path.Match(strings.ToLower(p), lower); ok {
			return true
		}
	}
	for _, seg := range strings.Split(lower, "/") {
		if seg == ".git" {
			return true
		}
		for _, p := range e.names {
			if ok, _ := path.Match(strings.ToLower(p), seg); ok {
				return true
			}
		}
	}
	return false
}

// workspace est l'arborescence d'une analyse, vue par les outils du modèle et par le
// vérificateur. Tout accès passe par un os.Root ouvert sur le répertoire extrait : aucun
// chemin ne sort de l'arborescence, aucun lien n'est suivi hors d'elle. Les fichiers
// exclus (motifs, ou clé privée détectée dans le contenu) ne sont ni listés, ni lus, ni
// fouillés.
type workspace struct {
	root    *os.Root
	excl    exclusions
	maxRead int64 // octets que les outils peuvent renvoyer au modèle
	read    int64
}

// Bornes des outils.
const (
	maxListEntries  = 500
	maxReadLines    = 400
	maxReadBytes    = 32 << 10
	maxLineChars    = 2000
	maxSearchHits   = 50
	maxSearchFiles  = 20_000
	maxScannedFile  = 2 << 20 // un fichier plus gros n'est ni lu ni fouillé
	maxHitChars     = 300
	maxVerifyWindow = 64 << 10
	// maxKeySniff : listDir et le filtre du périmètre incrémental cherchent une clé privée
	// dans les fichiers de cette taille au plus (une clé tient en quelques Kio) ; au-delà,
	// le fichier est listé, puis refusé à la lecture s'il en contient une.
	maxKeySniff = 64 << 10
)

func openWorkspace(dir string, excl exclusions, maxRead int64) (*workspace, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("repoagent: répertoire d'analyse : %w", err)
	}
	return &workspace{root: root, excl: excl, maxRead: maxRead}, nil
}

func (w *workspace) Close() error { return w.root.Close() }

// clean ramène un chemin donné par le modèle à un chemin relatif propre ; refuse un
// chemin absolu ou qui remonte.
func (w *workspace) clean(p string) (string, error) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "./")
	if p == "" || p == "/" {
		return ".", nil
	}
	if strings.HasPrefix(p, "/") || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
		return "", errBadPath
	}
	c := path.Clean(p)
	if !filepath.IsLocal(filepath.FromSlash(c)) && c != "." {
		return "", errBadPath
	}
	return c, nil
}

// charge compte n octets renvoyés au modèle.
func (w *workspace) charge(n int) error {
	if w.maxRead > 0 && w.read+int64(n) > w.maxRead {
		return errReadBudget
	}
	w.read += int64(n)
	return nil
}

type dirEntry struct {
	Name string
	Dir  bool
	Size int64
}

// listDir liste un répertoire, sans les éléments exclus.
func (w *workspace) listDir(rel string) ([]dirEntry, bool, error) {
	rel, err := w.clean(rel)
	if err != nil {
		return nil, false, err
	}
	if w.excl.match(rel) {
		return nil, false, fs.ErrNotExist
	}
	entries, err := fs.ReadDir(w.root.FS(), rel)
	if err != nil {
		return nil, false, err
	}
	var out []dirEntry
	truncated := false
	for _, e := range entries {
		if w.excl.match(path.Join(rel, e.Name())) {
			continue
		}
		if e.Type().IsRegular() && w.holdsPrivateKey(path.Join(rel, e.Name())) {
			// Exclu par son contenu : ni listé, ni lu, comme un fichier absent (SEC2-07).
			continue
		}
		if len(out) == maxListEntries {
			truncated = true
			break
		}
		d := dirEntry{Name: e.Name(), Dir: e.IsDir()}
		if info, err := e.Info(); err == nil && !e.IsDir() {
			d.Size = info.Size()
		}
		out = append(out, d)
	}
	return out, truncated, nil
}

// holdsPrivateKey indique si le fichier régulier rel, de maxKeySniff octets au plus,
// contient une clé privée (content le refuserait). Une erreur de lecture vaut « non » :
// la lecture refusera le fichier de toute façon.
func (w *workspace) holdsPrivateKey(rel string) bool {
	f, err := w.root.Open(rel)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxKeySniff {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeySniff+1))
	if err != nil {
		return false
	}
	for _, m := range privateKeyMarkers {
		if m.Match(data) {
			return true
		}
	}
	return false
}

// visible indique si un chemin du dépôt peut être nommé au modèle : ni exclu par un
// motif, ni fichier à clé privée détectée (SEC2-07). Un chemin absent reste visible (un
// fichier supprimé d'une analyse incrémentale).
func (w *workspace) visible(rel string) bool {
	c, err := w.clean(rel)
	if err != nil {
		return false
	}
	return !w.excl.match(c) && !w.holdsPrivateKey(c)
}

// content lit un fichier entier (borné), refuse un fichier exclu, binaire ou qui contient
// une clé privée.
func (w *workspace) content(rel string) ([]byte, error) {
	rel, err := w.clean(rel)
	if err != nil {
		return nil, err
	}
	if rel == "." || w.excl.match(rel) {
		return nil, errExcluded
	}
	f, err := w.root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotText
	}
	if info.Size() > maxScannedFile {
		return nil, errNotText
	}
	data, err := io.ReadAll(io.LimitReader(f, maxScannedFile+1))
	if err != nil {
		return nil, err
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil, errNotText
	}
	for _, m := range privateKeyMarkers {
		if m.Match(data) {
			return nil, errExcluded
		}
	}
	return data, nil
}

// splitLines découpe un contenu en lignes, sans fin de ligne.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// excerpt est une plage de lignes d'un fichier.
type excerpt struct {
	Path      string `json:"path"`
	Start     int    `json:"start_line"`
	End       int    `json:"end_line"`
	Total     int    `json:"total_lines"`
	Truncated bool   `json:"truncated,omitempty"`
	// Content : lignes numérotées « n<TAB>texte ».
	Content string `json:"content"`
}

// readLines lit les lignes from à to (1-based, incluses) pour le modèle, bornées en
// nombre et en octets, et les décompte du budget de lecture.
func (w *workspace) readLines(rel string, from, to int) (excerpt, error) {
	data, err := w.content(rel)
	if err != nil {
		return excerpt{}, err
	}
	clean, _ := w.clean(rel)
	lines := splitLines(data)
	if from < 1 {
		from = 1
	}
	if to < from || to > from+maxReadLines-1 {
		to = from + maxReadLines - 1
	}
	if to > len(lines) {
		to = len(lines)
	}
	ex := excerpt{Path: clean, Start: from, Total: len(lines)}
	var b strings.Builder
	for i := from; i <= to; i++ {
		line := lines[i-1]
		if utf8.RuneCountInString(line) > maxLineChars {
			line = string([]rune(line)[:maxLineChars]) + "…"
			ex.Truncated = true
		}
		next := fmt.Sprintf("%d\t%s\n", i, line)
		if b.Len()+len(next) > maxReadBytes {
			ex.Truncated = true
			break
		}
		b.WriteString(next)
		ex.End = i
	}
	ex.Content = b.String()
	if err := w.charge(len(ex.Content)); err != nil {
		return excerpt{}, err
	}
	return ex, nil
}

// searchHit est une ligne trouvée par search.
type searchHit struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// search cherche re dans les fichiers texte non exclus dont le chemin correspond à glob
// (motif path.Match sur le chemin, ou sur le nom s'il n'a pas de « / » ; vide : tous),
// au plus max résultats, dans l'ordre des chemins.
func (w *workspace) search(re *regexp.Regexp, glob string, max int) ([]searchHit, bool, error) {
	if max < 1 || max > maxSearchHits {
		max = maxSearchHits
	}
	var paths []string
	err := fs.WalkDir(w.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p != "." && w.excl.match(p) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if glob != "" {
			target := p
			if !strings.Contains(glob, "/") {
				target = path.Base(p)
			}
			if ok, _ := path.Match(glob, target); !ok {
				return nil
			}
		}
		paths = append(paths, p)
		if len(paths) >= maxSearchFiles {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	sort.Strings(paths)
	var hits []searchHit
	size := 0
	for _, p := range paths {
		data, err := w.content(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), maxScannedFile+1)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			loc := re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if len(hits) == max {
				return hits, true, w.charge(size)
			}
			hits = append(hits, searchHit{Path: p, Line: n, Text: around(line, loc, maxHitChars)})
			size += len(p) + len(hits[len(hits)-1].Text) + 16
		}
	}
	return hits, false, w.charge(size)
}

// around renvoie au plus n caractères de line autour de la correspondance loc.
func around(line string, loc []int, n int) string {
	if utf8.RuneCountInString(line) <= n {
		return line
	}
	start := max(loc[0]-n/3, 0)
	for start > 0 && !utf8.RuneStart(line[start]) {
		start--
	}
	r := []rune(line[start:])
	if len(r) > n {
		r = r[:n]
	}
	prefix := ""
	if start > 0 {
		prefix = "…"
	}
	return prefix + string(r) + "…"
}
