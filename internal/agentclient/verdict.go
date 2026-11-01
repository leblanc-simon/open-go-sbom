package agentclient

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agentclient/gen"
)

// États d'un verdict (gen.Verdict.State).
const (
	VerdictPending = "pending"
	VerdictPass    = "pass"
	VerdictFail    = "fail"
)

// Verdict renvoie le verdict des politiques sur un instantané envoyé par l'agent (T15).
func (c *Client) Verdict(ctx context.Context, snapshotID uuid.UUID) (gen.Verdict, error) {
	rsp, err := c.gen.GetSnapshotVerdictWithResponse(withOp(ctx, "getSnapshotVerdict"), snapshotID, c.editor(""))
	if err != nil {
		return gen.Verdict{}, wrapTransport("getSnapshotVerdict", err)
	}
	if rsp.JSON200 == nil {
		return gen.Verdict{}, responseError("getSnapshotVerdict", rsp.HTTPResponse, rsp.Body)
	}
	return *rsp.JSON200, nil
}

// WaitVerdict interroge le verdict d'un instantané jusqu'à ce qu'il ne soit plus en
// attente, toutes les poll au début puis à intervalle doublé jusqu'à 30 s ; ctx borne
// l'attente (son échéance rend le dernier verdict lu, en attente, avec l'erreur du
// contexte).
func (c *Client) WaitVerdict(ctx context.Context, snapshotID uuid.UUID, poll time.Duration) (gen.Verdict, error) {
	if poll <= 0 {
		poll = time.Second
	}
	const maxPoll = 30 * time.Second
	v := gen.Verdict{State: VerdictPending}
	for {
		next, err := c.Verdict(ctx, snapshotID)
		if err != nil {
			return v, err
		}
		v = next
		if v.State != VerdictPending {
			return v, nil
		}
		if err := sleepContext(ctx, poll); err != nil {
			return v, fmt.Errorf("agentclient: attente du verdict de %s : %w", snapshotID, err)
		}
		poll = min(2*poll, maxPoll)
	}
}
