package agent

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
)

// silentPage borne les agents lus par requête lors du décompte des agents muets.
const silentPage = 500

// Silent parcourt les agents non désactivés de l'organisation de tx et renvoie le nombre
// d'agents muets à l'instant now, avec les keep plus longtemps silencieux (dernier contact
// le plus ancien d'abord). L'état est celui de Agent.StateAt, la règle des écrans des
// agents : le tableau de bord ne la recalcule pas. Lecture par pages, mémoire bornée par
// keep.
func Silent(ctx context.Context, tx *db.OrgTx, now time.Time, keep int) (int, []Agent, error) {
	count := 0
	var longest []Agent
	after := uuid.Nil
	for {
		rows, err := tx.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents a
			 WHERE a.disabled_at IS NULL AND a.id > $2 ORDER BY a.id LIMIT $3`, now, after, silentPage)
		if err != nil {
			return 0, nil, wrap("agents muets", err)
		}
		n := 0
		for rows.Next() {
			a, err := scanAgent(rows)
			if err != nil {
				rows.Close()
				return 0, nil, wrap("agents muets", err)
			}
			n++
			after = a.ID
			if a.StateAt(now) != StateSilent {
				continue
			}
			count++
			longest = keepLongest(longest, a, keep)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, nil, wrap("agents muets", err)
		}
		rows.Close()
		if n < silentPage {
			return count, longest, nil
		}
	}
}

// keepLongest insère a parmi les keep agents au dernier contact le plus ancien (puis par
// nom), triés.
func keepLongest(list []Agent, a Agent, keep int) []Agent {
	if keep <= 0 {
		return list
	}
	i, _ := slices.BinarySearchFunc(list, a, compareSilence)
	if i >= keep {
		return list
	}
	list = slices.Insert(list, i, a)
	if len(list) > keep {
		list = list[:keep]
	}
	return list
}

func compareSilence(x, y Agent) int {
	if c := x.SilentSince().Compare(y.SilentSince()); c != 0 {
		return c
	}
	if c := strings.Compare(x.Name, y.Name); c != 0 {
		return c
	}
	return bytes.Compare(x.ID[:], y.ID[:])
}

// SilentSince renvoie l'instant d'où se compte le silence d'un agent (Activity.Since :
// dernier inventaire d'un agent serveur, dernier contact d'un agent dépôt).
func (a Agent) SilentSince() time.Time { return a.Activity().Since().UTC() }
