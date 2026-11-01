package forge

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"unicode/utf8"
)

// StatusState est l'état d'un statut de commit, dans le vocabulaire de GitHub ; GitLab
// en a un équivalent (statusStateGitLab).
type StatusState string

// États d'un statut de commit.
const (
	StatusPending StatusState = "pending" // analyse ou évaluation en cours
	StatusSuccess StatusState = "success" // conforme aux politiques
	StatusFailure StatusState = "failure" // non conforme : violation d'une politique bloquante
	StatusError   StatusState = "error"   // verdict indisponible (délai dépassé, serveur injoignable)
)

// CommitStatus est un statut de commit à publier (T15, ADR 0047).
type CommitStatus struct {
	State StatusState
	// Context nomme le statut sur la forge (« lotor ») : un nouveau statut du même nom
	// remplace le précédent.
	Context     string
	Description string
	// TargetURL mène au détail sur le serveur lotor ; vide : sans lien.
	TargetURL string
}

// maxStatusDescription : GitHub refuse une description de plus de 140 caractères.
const maxStatusDescription = 140

// ErrStatus : statut de commit invalide (état inconnu, contexte vide, commit illisible).
var ErrStatus = errors.New("forge: statut de commit invalide")

func (s CommitStatus) clean(commit string) (CommitStatus, error) {
	switch s.State {
	case StatusPending, StatusSuccess, StatusFailure, StatusError:
	default:
		return s, ErrStatus
	}
	if s.Context == "" || !ValidCommit(commit) {
		return s, ErrStatus
	}
	if utf8.RuneCountInString(s.Description) > maxStatusDescription {
		r := []rune(s.Description)
		s.Description = string(r[:maxStatusDescription-1]) + "…"
	}
	if s.TargetURL != "" {
		if u, err := url.Parse(s.TargetURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			s.TargetURL = ""
		}
	}
	return s, nil
}

// SetStatus publie un statut de commit par l'API des statuts de GitHub, avec un jeton
// d'installation restreint au dépôt et à « statuses: write » (en plus de la lecture du
// contenu, demandée pour le clonage par un autre jeton) : l'application doit avoir la
// permission « Commit statuses : Read and write ».
func (g *GitHub) SetStatus(ctx context.Context, repo, commit string, s CommitStatus) error {
	s, err := s.clean(commit)
	if err != nil {
		return err
	}
	tok, err := g.tokenFor(ctx, repo, map[string]string{"statuses": "write"}, "statuses\x00")
	if err != nil {
		return err
	}
	body := map[string]string{"state": string(s.State), "context": s.Context, "description": s.Description}
	if s.TargetURL != "" {
		body["target_url"] = s.TargetURL
	}
	return call(ctx, g.client, http.MethodPost, g.api+"/repos/"+repo+"/statuses/"+commit, g.headers("Bearer "+tok), body, nil)
}

// statusStateGitLab traduit un état : GitLab n'a pas d'état « error », un verdict
// indisponible devient « canceled » pour ne pas se lire comme un échec des politiques.
func statusStateGitLab(s StatusState) string {
	switch s {
	case StatusSuccess:
		return "success"
	case StatusFailure:
		return "failed"
	case StatusError:
		return "canceled"
	}
	return "pending"
}

// SetStatus publie un statut de commit par l'API des statuts de GitLab : le jeton du
// compte de service doit avoir la portée « api » et le rôle Developer sur le projet.
func (g *GitLab) SetStatus(ctx context.Context, repo, commit string, s CommitStatus) error {
	s, err := s.clean(commit)
	if err != nil {
		return err
	}
	body := map[string]string{"state": statusStateGitLab(s.State), "name": s.Context, "description": s.Description}
	if s.TargetURL != "" {
		body["target_url"] = s.TargetURL
	}
	header := http.Header{
		"Private-Token": {g.cfg.Token},
		"Accept":        {"application/json"},
		"User-Agent":    {"lotor-repo-agent"},
	}
	return call(ctx, g.client, http.MethodPost, g.web.String()+"/api/v4"+g.project(repo)+"/statuses/"+commit, header, body, nil)
}
