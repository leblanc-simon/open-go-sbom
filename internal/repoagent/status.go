package repoagent

import (
	"context"
	"log/slog"
	"time"

	"leblanc.io/lotor/internal/forge"
)

// StatusConfig règle la publication du statut de commit (T15, ADR 0047) : après l'envoi
// d'un SBOM, l'agent attend le verdict des politiques au plus Timeout, puis le publie sur
// la forge sous le nom Context.
type StatusConfig struct {
	Enabled bool          `yaml:"enabled" env:"STATUS_ENABLED" env-description:"Publish the policy verdict as a commit status on the forge (needs the commit status permission; default false)"`
	Context string        `yaml:"context" env:"STATUS_CONTEXT" env-default:"lotor" env-description:"Name of the commit status on the forge"`
	Timeout time.Duration `yaml:"timeout" env:"STATUS_TIMEOUT" env-default:"15m"   env-description:"Maximum wait for the verdict after an upload (the next commit waits meanwhile)"`
	Poll    time.Duration `yaml:"poll"    env:"STATUS_POLL"    env-default:"5s"    env-description:"First interval between two verdict queries, doubled up to 30s"`
}

// maxStatusPoll plafonne l'intervalle d'interrogation du verdict.
const maxStatusPoll = 30 * time.Second

// stateOf traduit un verdict en état de statut de commit.
func stateOf(v PolicyVerdict) forge.StatusState {
	switch v.State {
	case VerdictPass:
		return forge.StatusSuccess
	case VerdictFail:
		return forge.StatusFailure
	case VerdictError:
		return forge.StatusError
	}
	return forge.StatusPending
}

// reportStatus attend le verdict d'un envoi et le publie comme statut du commit : un
// statut « en attente » dès que le serveur fournit son résumé, puis le verdict. Le délai
// passé, le statut reste « en attente » (le verdict n'est pas connu, l'agent ne l'invente
// pas). Une erreur n'arrête rien : le SBOM est envoyé, elle est seulement journalisée.
func (a *Agent) reportStatus(ctx context.Context, t tracked, commit string, rc Receipt) {
	cfg := a.opts.Status
	if !cfg.Enabled {
		return
	}
	log := a.log.With("project", t.project.Slug, "ref", t.ref.Ref.Name, "commit", commit)
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	poll := max(cfg.Poll, 100*time.Millisecond)
	pendingSent := false
	for {
		v, err := a.opts.Server.Verdict(ctx, rc)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("verdict illisible : statut de commit non publié", "err", err)
			}
			return
		}
		if v.State != VerdictPending {
			a.publish(ctx, log, t, commit, v)
			return
		}
		if !pendingSent && v.Summary != "" {
			pendingSent = a.publish(ctx, log, t, commit, v)
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			log.Warn("verdict non rendu dans le délai : statut de commit laissé en attente", "timeout", cfg.Timeout)
			return
		case <-timer.C:
		}
		poll = min(2*poll, maxStatusPoll)
	}
}

// publish publie un statut ; faux en cas d'échec (journalisé sans secret).
func (a *Agent) publish(ctx context.Context, log *slog.Logger, t tracked, commit string, v PolicyVerdict) bool {
	s := forge.CommitStatus{State: stateOf(v), Context: a.opts.Status.Context, Description: v.Summary, TargetURL: v.URL}
	if err := t.forge.SetStatus(ctx, t.repo, commit, s); err != nil {
		log.Warn("publication du statut de commit en échec", "state", s.State, "err", err)
		return false
	}
	log.Info("statut de commit publié", "state", s.State)
	return true
}
