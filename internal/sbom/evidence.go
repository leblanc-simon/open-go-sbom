package sbom

import "encoding/json"

// Occurrence est la première occurrence de la preuve (champ evidence de CycloneDX) d'un
// composant : fichier, ligne et extrait, tels que l'enrichissement IA les écrit.
type Occurrence struct {
	Location string
	Line     int
	Excerpt  string
}

// FirstOccurrence lit la première occurrence d'une preuve ; faux si la preuve n'en a pas
// (ou n'est pas lisible). L'extrait vient d'additionalContext, à défaut de la valeur de la
// première méthode d'identification.
func FirstOccurrence(evidence json.RawMessage) (Occurrence, bool) {
	if len(evidence) == 0 {
		return Occurrence{}, false
	}
	var ev struct {
		Occurrences []struct {
			Location          string `json:"location"`
			Line              int    `json:"line"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"occurrences"`
		Identity json.RawMessage `json:"identity"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil || len(ev.Occurrences) == 0 || ev.Occurrences[0].Location == "" {
		return Occurrence{}, false
	}
	o := ev.Occurrences[0]
	out := Occurrence{Location: o.Location, Line: o.Line, Excerpt: o.AdditionalContext}
	if out.Excerpt == "" {
		var ids []struct {
			Methods []struct {
				Value string `json:"value"`
			} `json:"methods"`
		}
		if json.Unmarshal(ev.Identity, &ids) == nil && len(ids) > 0 && len(ids[0].Methods) > 0 {
			out.Excerpt = ids[0].Methods[0].Value
		}
	}
	return out, true
}
