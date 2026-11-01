package repoagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"leblanc.io/lotor/internal/llm/llmtest"
	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// Critère de la recette du lot 2 (T18) : aucun composant d'origine IA n'entre dans un SBOM
// sans preuve vérifiée. Le vérificateur en est le seul juge (ADR 0043) ; ces tests le
// contrôlent de l'extérieur : des modèles fictifs aussi crédules et hostiles que possible
// soumettent des centaines de candidats tirés des fichiers réels, et chaque composant IA du
// SBOM envoyé au serveur (relu par le décodeur du serveur) est revérifié contre le dépôt
// par checkProof, qui ne réutilise pas le code du vérificateur.

// versionToken repère, dans une ligne, un nom suivi d'un numéro de version : la matière
// d'un modèle qui prendrait tout numéro pour un composant.
var versionToken = regexp.MustCompile(`([A-Za-z][A-Za-z0-9._/-]{1,60})[@: =_"'-]{1,4}v?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.]+)?)`)

// greedyCandidates propose, pour chaque ligne d'un fichier texte du dépôt qui porte un nom
// suivi d'une version, un candidat dont l'extrait est la ligne elle-même : documentation,
// manifestes, commentaires et code du dépôt compris. Au plus limit candidats.
func greedyCandidates(dir string, limit int) []Candidate {
	var out []Candidate
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || len(out) >= limit {
			return filepath.SkipAll
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 256<<10 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || strings.ContainsRune(string(data[:min(len(data), 8000)]), 0) {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range versionToken.FindAllStringSubmatch(line, 3) {
				name := strings.Trim(m[1][strings.LastIndex(m[1], "/")+1:], "._-")
				if name == "" || len(out) >= limit {
					continue
				}
				excerpt := strings.TrimSpace(line)
				if len(excerpt) > 400 {
					excerpt = excerpt[:400]
				}
				purl := packageurl.NewPackageURL("generic", "", name, m[2], nil, "").ToString()
				typ := "generic"
				if strings.HasPrefix(strings.ToLower(path.Base(rel)), "dockerfile") || strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml") {
					typ = "docker"
				}
				if typ == "docker" {
					purl = packageurl.NewPackageURL("docker", "library", name, m[2], nil, "").ToString()
				}
				out = append(out, Candidate{Name: name, Version: m[2], PURL: purl, File: rel, Line: i + 1, Excerpt: excerpt, Confidence: 0.5})
			}
		}
		return nil
	})
	return out
}

// mutations dérive d'un candidat des variantes fausses ou de forme douteuse : ligne hors
// tolérance, version voisine, chemins qui sortent de l'arborescence, absolus ou détournés,
// extrait d'une autre version, purl d'un autre nom ou d'un type incohérent.
func mutations(c Candidate, dir string) []Candidate {
	far, bumped, up, abs, dot, other, renamed, docker := c, c, c, c, c, c, c, c
	far.Line += 10
	bumped.Version += ".9"
	bumped.PURL += ".9"
	up.File = "../" + c.File
	abs.File = filepath.Join(dir, c.File)
	dot.File = "./" + c.File
	other.Excerpt = strings.Replace(c.Excerpt, c.Version, c.Version+"0", 1)
	renamed.Name, renamed.PURL = "evil-"+c.Name, strings.Replace(c.PURL, "/"+c.Name+"@", "/evil-"+c.Name+"@", 1)
	docker.PURL = packageurl.NewPackageURL("docker", "library", c.Name, c.Version, nil, "").ToString()
	return []Candidate{far, bumped, up, abs, dot, other, renamed, docker}
}

// adversarialCandidates réunit tout ce qu'un modèle crédule ou détourné pourrait soumettre
// pour un cas : les composants annotés, les pièges avec leur meilleure preuve, des versions
// inventées, les candidats demandés par les instructions malveillantes, la récolte de
// greedyCandidates et les mutations de chacun.
func adversarialCandidates(t *testing.T, c corpusCase, dir string) []Candidate {
	t.Helper()
	out := naiveCandidates(t, c, dir)
	if c.Hostile {
		out = append(out, hostileCandidates(c)...)
	}
	greedy := greedyCandidates(dir, 400)
	out = append(out, greedy...)
	for _, g := range append(oracleCandidates(c), greedy[:min(len(greedy), 60)]...) {
		out = append(out, mutations(g, dir)...)
	}
	return out
}

// proofRun est le résultat de l'analyse d'un cas par un modèle fictif, soumission par
// soumission (maxCandidates au plus chacune).
type proofRun struct {
	Submitted, Accepted, Rejected int
	Checked                       int // composants IA du SBOM revérifiés par checkProof
	Accepts                       []AcceptedComponent
}

// runAdversarial fait analyser dir par un modèle fictif qui soumet cands, par lots, en
// commençant chaque analyse par les lectures hostiles quand le cas l'est ; chaque SBOM
// produit passe par checkProof.
func runAdversarial(t *testing.T, c corpusCase, dir string, cands []Candidate) proofRun {
	t.Helper()
	var run proofRun
	for start := 0; start < len(cands); start += maxCandidates {
		batch := cands[start:min(start+maxCandidates, len(cands))]
		var steps []llmtest.Step
		if c.Hostile {
			steps = append(steps, llmtest.Tools(hostileCalls()...))
		}
		steps = append(steps, submitOf(batch...))
		script := &llmtest.Script{ModelName: "fictif", IsExternal: true, Steps: steps}
		res := newTestEnricher(t, script).enrich(context.Background(), enrichInput{Dir: dir, Project: c.Name, Commit: commitN(1), Mode: AIExternal})
		if res.Status != EnrichmentComplete {
			t.Fatalf("%s : %+v", c.Name, res)
		}
		run.Submitted += len(batch)
		run.Accepted += len(res.Accepted)
		run.Rejected += res.Verdict.RejectedCount()
		run.Accepts = append(run.Accepts, res.Accepted...)
		run.Checked += assertEveryAIComponentProven(t, c.Name, dir, res)
	}
	return run
}

// assertEveryAIComponentProven fusionne le résultat dans un SBOM vide, l'encode, le relit
// par le décodeur du serveur et revérifie chaque composant d'origine IA ; il renvoie le
// nombre de composants vérifiés.
func assertEveryAIComponentProven(t testing.TB, name, dir string, res enrichResult) int {
	t.Helper()
	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: name}}
	bom.Components = &[]cyclonedx.Component{}
	mergeAI(bom, res, func(rel string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil
		}
		return data
	})
	data, err := encodeBOM(bom)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbomsyft.Decode(sbom.FormatCycloneDX, data)
	if err != nil {
		t.Fatalf("%s : SBOM illisible par le serveur : %v", name, err)
	}
	n := 0
	for _, comp := range doc.Components {
		if comp.Origin != sbom.OriginIA {
			continue
		}
		n++
		if err := checkProof(dir, comp); err != nil {
			t.Errorf("%s : composant IA sans preuve vérifiée %s : %v", name, comp.PURL, err)
		}
	}
	if n != len(res.Accepted) {
		t.Errorf("%s : %d composants IA dans le SBOM pour %d acceptés", name, n, len(res.Accepted))
	}
	return n
}

var proofSpaces = regexp.MustCompile(`\s+`)

func proofNorm(s string) string { return strings.TrimSpace(proofSpaces.ReplaceAllString(s, " ")) }

// proofSep retire casse et séparateurs, pour comparer un nom à son écriture dans le
// fichier (GOLANGCI_LINT pour golangci-lint).
func proofSep(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune("-_. ", r) {
			return -1
		}
		return r
	}, strings.ToLower(s))
}

// checkProof revérifie la preuve d'un composant IA relu par le serveur, indépendamment du
// vérificateur : chemin relatif propre, fichier ordinaire du dépôt atteint sans lien
// symbolique, jamais exclu ni porteur d'un secret, extrait présent à la ligne annoncée
// (ou commençant sur elle), version et nom dans la preuve, empreinte du fichier exacte.
func checkProof(dir string, comp sbom.Component) error {
	occ, ok := sbom.FirstOccurrence(comp.Evidence)
	if !ok {
		return errors.New("aucune occurrence")
	}
	loc := occ.Location
	if loc == "" || strings.HasPrefix(loc, "/") || strings.Contains(loc, `\`) || path.Clean(loc) != loc || loc == "." {
		return fmt.Errorf("chemin %q", loc)
	}
	segs := strings.Split(loc, "/")
	for _, seg := range segs {
		if seg == ".." || seg == ".git" {
			return fmt.Errorf("chemin %q", loc)
		}
		for _, pat := range DefaultExclude {
			if m, _ := path.Match(pat, seg); m && !strings.Contains(pat, "/") {
				return fmt.Errorf("fichier exclu %q (%s)", loc, pat)
			}
		}
	}
	for _, pat := range DefaultExclude {
		if m, _ := path.Match(pat, loc); m && strings.Contains(pat, "/") {
			return fmt.Errorf("fichier exclu %q (%s)", loc, pat)
		}
	}
	cur := dir
	for _, seg := range segs {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("lien symbolique %q", loc)
		}
	}
	data, err := os.ReadFile(cur)
	if err != nil {
		return err
	}
	if strings.Contains(string(data), "LOTOR-CANARY") || strings.Contains(string(data), "PRIVATE KEY") {
		return fmt.Errorf("fichier porteur d'un secret %q", loc)
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if occ.Line < 1 || occ.Line > len(lines) {
		return fmt.Errorf("ligne %d hors du fichier (%d lignes)", occ.Line, len(lines))
	}
	ex := proofNorm(occ.Excerpt)
	first := proofNorm(lines[occ.Line-1])
	window := proofNorm(strings.Join(lines[occ.Line-1:min(occ.Line+3, len(lines))], "\n"))
	if i := strings.Index(window, ex); len(ex) < 3 || i < 0 || i >= len(first)+1 {
		return fmt.Errorf("extrait %q absent de la ligne %d", occ.Excerpt, occ.Line)
	}
	version := strings.TrimPrefix(strings.ToLower(comp.Version), "v")
	if version == "" || !strings.Contains(strings.ToLower(ex), version) {
		return fmt.Errorf("version %q absente de l'extrait %q", comp.Version, occ.Excerpt)
	}
	around := proofNorm(strings.Join(lines[max(occ.Line-4, 0):min(occ.Line+3, len(lines))], "\n"))
	if !strings.Contains(proofSep(around), proofSep(comp.Name)) {
		return fmt.Errorf("nom %q absent de la preuve", comp.Name)
	}
	for _, h := range comp.Hashes {
		sum := sha256.Sum256(data)
		if h != "sha256:"+hex.EncodeToString(sum[:]) {
			return fmt.Errorf("empreinte %s fausse pour %q", h, loc)
		}
	}
	return nil
}

// TestNoAIComponentWithoutVerifiedProof : sur chaque cas du corpus, un modèle fictif qui
// soumet tout ce qu'il trouve (composants annotés, pièges, versions inventées,
// instructions malveillantes, centaines de lignes porteuses d'un numéro, chemins détournés,
// liens symboliques) n'obtient l'entrée d'aucun composant IA dont la preuve ne se revérifie
// pas ; les composants annotés passent tous (le contrôle n'est pas vide).
func TestNoAIComponentWithoutVerifiedProof(t *testing.T) {
	var submitted, accepted, rejected, checked int
	for _, c := range loadCorpus(t) {
		t.Run(c.Name, func(t *testing.T) {
			dir := stage(t, c)
			// Liens symboliques plantés dans le dépôt : vers un témoin hors de l'arborescence,
			// et vers un fichier ordinaire du dépôt (une preuve ne passe jamais par un lien).
			if err := os.Symlink("../../outside-canary.txt", filepath.Join(dir, "linked-outside.js")); err != nil {
				t.Fatal(err)
			}
			cands := adversarialCandidates(t, c, dir)
			for _, o := range oracleCandidates(c) {
				link := "linked-" + strings.ReplaceAll(o.File, "/", "-")
				if err := os.Symlink(o.File, filepath.Join(dir, link)); err != nil && !errors.Is(err, fs.ErrExist) {
					t.Fatal(err)
				}
				l := o
				l.File = link
				cands = append(cands, l)
			}
			cands = append(cands, Candidate{Name: "outside", Version: "1.0.0", PURL: "pkg:npm/outside@1.0.0", File: "linked-outside.js",
				Line: 1, Excerpt: outsideCanary, Confidence: 1})
			run := runAdversarial(t, c, dir, cands)
			s := scoreCase(t, c, run.Accepts)
			if s.FN != 0 {
				t.Errorf("composants annotés perdus : %v", s.Missed)
			}
			for _, a := range run.Accepts {
				if strings.HasPrefix(a.File, "linked-") {
					t.Errorf("preuve acceptée par un lien symbolique : %s", a.File)
				}
			}
			submitted, accepted, rejected, checked = submitted+run.Submitted, accepted+run.Accepted, rejected+run.Rejected, checked+run.Checked
		})
	}
	if checked == 0 || checked != accepted {
		t.Fatalf("%d composants revérifiés pour %d acceptés", checked, accepted)
	}
	t.Logf("corpus : %d candidats soumis, %d acceptés (tous revérifiés), %d rejetés", submitted, accepted, rejected)
}

// TestCheckProofRejectsForgedEvidence : checkProof n'est pas une formalité ; il refuse une
// preuve qui ne figure pas dans le dépôt.
func TestCheckProofRejectsForgedEvidence(t *testing.T) {
	dir := stage(t, corpusCaseNamed(t, "vendored-js"))
	ev := func(loc string, line int, excerpt string) []byte {
		return fmt.Appendf(nil, `{"occurrences":[{"location":%q,"line":%d,"additionalContext":%q}]}`, loc, line, excerpt)
	}
	good := sbom.Component{Name: "jquery", Version: "3.4.1", Origin: sbom.OriginIA, Evidence: ev("public/js/vendor/jquery.min.js", 1, "jQuery v3.4.1")}
	if err := checkProof(dir, good); err != nil {
		t.Fatalf("preuve réelle refusée : %v", err)
	}
	if err := os.Symlink("public/js/vendor/jquery.min.js", filepath.Join(dir, "link.js")); err != nil {
		t.Fatal(err)
	}
	forged := map[string]sbom.Component{
		"sans preuve":     {Name: "jquery", Version: "3.4.1"},
		"version fausse":  {Name: "jquery", Version: "3.7.1", Evidence: good.Evidence},
		"nom faux":        {Name: "lodash", Version: "3.4.1", Evidence: good.Evidence},
		"ligne fausse":    {Name: "jquery", Version: "3.4.1", Evidence: ev("public/js/vendor/jquery.min.js", 99, "jQuery v3.4.1")},
		"extrait inventé": {Name: "jquery", Version: "3.4.1", Evidence: ev("public/js/vendor/jquery.min.js", 1, "jquery 3.4.1 inside")},
		"hors dépôt":      {Name: "jquery", Version: "3.4.1", Evidence: ev("../outside-canary.txt", 1, "jQuery v3.4.1")},
		"lien":            {Name: "jquery", Version: "3.4.1", Evidence: ev("link.js", 1, "jQuery v3.4.1")},
		"absolu":          {Name: "jquery", Version: "3.4.1", Evidence: ev(filepath.Join(dir, "public/js/vendor/jquery.min.js"), 1, "jQuery v3.4.1")},
		"empreinte":       {Name: "jquery", Version: "3.4.1", Evidence: good.Evidence, Hashes: []string{"sha256:00"}},
	}
	for name, c := range forged {
		if err := checkProof(dir, c); err == nil {
			t.Errorf("%s : preuve forgée acceptée", name)
		}
	}
}
