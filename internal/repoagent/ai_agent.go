package repoagent

import (
	"context"
	"os"

	"github.com/CycloneDX/cyclonedx-go"
)

// enrich ajoute au SBOM Syft d'un commit l'enrichissement IA permis par le réglage du
// projet. Un projet sans IA permise (ou sans modèle configuré pour son réglage) n'appelle
// aucun modèle et son SBOM reste celui de Syft, sans propriété d'enrichissement.
//
// Analyse incrémentale : le modèle reçoit la liste des fichiers modifiés depuis le
// dernier commit qu'il a analysé (comparaison de la forge, le clone superficiel n'ayant pas
// d'historique) et les composants IA précédents, revérifiés au nouveau commit. Analyse
// complète au premier passage, après un redémarrage sans état, à full_interval, ou si la
// comparaison échoue. Un commit intermédiaire d'un rattrapage ne fait que reporter les
// composants précédents encore prouvés, sans appel au modèle.
func (a *Agent) enrich(ctx context.Context, k refKey, t tracked, src, commit string, head bool, bom *cyclonedx.BOM) {
	mode := t.project.AIMode
	if mode == "" || mode == AIDisabled || a.ai.provider(mode) == nil {
		return
	}
	log := a.log.With("project", t.project.Slug, "ref", t.ref.Ref.Name, "commit", commit)
	a.mu.RLock()
	st, known := a.aiState[k]
	a.mu.RUnlock()
	if !known && t.ref.ID != "" {
		prev, err := a.opts.Server.AIComponents(ctx, t.ref.ID)
		if err != nil {
			log.Warn("composants IA précédents illisibles : analyse complète", "err", err)
		}
		st = aiState{components: prev}
	}
	in := enrichInput{Dir: src, Project: t.project.Slug, Commit: commit, Mode: mode, Previous: st.components}
	start := a.now()
	var res enrichResult
	if !head {
		res = a.ai.carry(in)
	} else {
		full := !known || st.commit == "" || a.now().Sub(st.fullAt) >= a.opts.AI.FullInterval
		if !full {
			cmp, err := t.forge.Compare(ctx, t.repo, st.commit, commit)
			if err != nil {
				log.Warn("comparaison impossible : analyse IA complète", "err", err)
				full = true
			} else {
				in.Scope = append([]string{}, cmp.Files...)
			}
		}
		res = a.ai.enrich(ctx, in)
		if res.Status == EnrichmentComplete {
			next := aiState{commit: commit, components: previousOf(res.Accepted), fullAt: st.fullAt}
			if full {
				next.fullAt = a.now()
			}
			a.mu.Lock()
			a.aiState[k] = next
			a.mu.Unlock()
		}
	}
	a.ai.logResult(log, res, a.now().Sub(start))
	mergeAI(bom, res, evidenceReader(src))
}

// evidenceReader lit un fichier de preuve dans l'arborescence de l'analyse (par os.Root),
// pour l'empreinte d'une bibliothèque recopiée.
func evidenceReader(src string) func(string) []byte {
	return func(rel string) []byte {
		root, err := os.OpenRoot(src)
		if err != nil {
			return nil
		}
		defer root.Close()
		data, err := root.ReadFile(rel)
		if err != nil || len(data) > maxScannedFile {
			return nil
		}
		return data
	}
}
