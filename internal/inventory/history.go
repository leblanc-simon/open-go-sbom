package inventory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/version"
)

// DiffKind est le type du job qui calcule et enregistre les différences des instantanés
// consécutifs d'une référence. Mis en file à chaque instantané créé ou remplacé, et par la
// rétention pour les références dont l'historique a changé ; la clé d'unicité fond les
// mises en file d'une même référence.
const DiffKind = "inventory.diff"

// DiffPayload est la charge d'un job inventory.diff.
type DiffPayload struct {
	RefID uuid.UUID `json:"ref_id"`
}

// DiffUniqueKey est la clé d'unicité du job de différences d'une référence.
func DiffUniqueKey(refID uuid.UUID) string { return "diff:" + refID.String() }

// enqueueDiff met en file le calcul des différences d'une référence.
func enqueueDiff(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) error {
	_, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: DiffKind, Payload: DiffPayload{RefID: refID}, Priority: jobs.PriorityNormal,
		UniqueKey: DiffUniqueKey(refID)})
	return err
}

// Bornes des pages d'une différence.
const (
	ChangePageDefault = 100
	ChangePageMax     = 500
)

// ErrInvalidChangeKind : nature de changement inconnue dans un filtre.
var ErrInvalidChangeKind = errors.New("inventory: nature de changement inconnue")

// ErrNoPrevious : l'instantané comparé à son précédent est le premier de sa référence.
var ErrNoPrevious = errors.New("inventory: instantané sans précédent")

// HistoryOptions réunit les dépendances de History.
type HistoryOptions struct {
	Pool     *db.Pool
	Comparer version.Comparer
	// Retention est la politique de rétention des instantanés (ADR 0039).
	Retention RetentionPolicy
	// Clock date les calculs et la rétention ; l'horloge du système par défaut.
	Clock  jobs.Clock
	Logger *slog.Logger
}

// History sert les différences entre instantanés (ADR 0038) et leur rétention
// (ADR 0039).
type History struct {
	pool   *db.Pool
	cmp    version.Comparer
	policy RetentionPolicy
	clock  jobs.Clock
	logger *slog.Logger
}

// NewHistory construit le service.
func NewHistory(o HistoryOptions) (*History, error) {
	if o.Pool == nil || o.Comparer == nil {
		return nil, errors.New("inventory: dépendances de l'historique incomplètes")
	}
	if err := o.Retention.Validate(); err != nil {
		return nil, err
	}
	if o.Clock == nil {
		o.Clock = jobs.SystemClock()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &History{pool: o.Pool, cmp: o.Comparer, policy: o.Retention, clock: o.Clock, logger: o.Logger}, nil
}

// Policy renvoie la politique de rétention (affichée par les écrans).
func (h *History) Policy() RetentionPolicy { return h.policy }

// DiffHandler est le handler de DiffKind : il calcule, une par transaction, les
// différences manquantes des instantanés consécutifs de la référence. Idempotent : une
// différence enregistrée n'est pas recalculée.
func (h *History) DiffHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(fmt.Errorf("inventory: %s sans organisation", DiffKind))
		}
		var p DiffPayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		_, err := h.ComputeMissing(ctx, e.OrgID, p.RefID)
		return err
	})
}

// ComputeMissing calcule et enregistre les différences manquantes des instantanés
// consécutifs d'une référence, et en renvoie le nombre.
func (h *History) ComputeMissing(ctx context.Context, org tenant.OrgID, refID uuid.UUID) (int, error) {
	var pairs [][2]uuid.UUID
	err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		pairs, err = missingDiffs(ctx, tx, refID)
		return err
	}, db.ReadOnly())
	if err != nil {
		return 0, wrap("différences à calculer", err)
	}
	for _, p := range pairs {
		err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
			changes, err := ComputeDiff(ctx, tx, h.cmp, p[0], p[1])
			if err != nil {
				return err
			}
			return storeDiff(ctx, tx, p[0], p[1], changes, h.clock.Now())
		})
		if err != nil {
			return 0, wrap("différence", err)
		}
	}
	return len(pairs), nil
}

// DiffRequest désigne une comparaison entre deux instantanés d'un projet.
type DiffRequest struct {
	ProjectID uuid.UUID
	// From est l'instantané de départ ; nul : le précédent de To dans sa référence.
	From uuid.UUID
	To   uuid.UUID
	// Kind restreint les changements listés (vide : tous).
	Kind   ChangeKind
	Cursor string
	Limit  int
}

// DiffResult est une comparaison : les deux instantanés, les comptes de chaque nature et
// une page des changements.
type DiffResult struct {
	From    Snapshot
	To      Snapshot
	Counts  DiffCounts
	Changes pagination.Page[Change]
	// Stored : la différence vient du stockage (couple consécutif déjà calculé).
	Stored bool
}

type changeCursor struct {
	K int    `json:"k"`
	B string `json:"b"`
	O string `json:"o"`
	N string `json:"n"`
}

func cursorOf(c Change) changeCursor {
	return changeCursor{K: c.Kind.rank(), B: c.PURLBase, O: sidePURL(c.Old), N: sidePURL(c.New)}
}

func (c changeCursor) before(x Change) bool {
	o := cursorOf(x)
	return cmp.Or(cmp.Compare(c.K, o.K), strings.Compare(c.B, o.B), strings.Compare(c.O, o.O), strings.Compare(c.N, o.N)) < 0
}

// Diff compare deux instantanés du projet : la différence enregistrée si le couple
// d'ensembles l'a déjà, sinon calculée à la demande. Un instantané d'un autre projet est
// introuvable.
func (h *History) Diff(ctx context.Context, org tenant.OrgID, req DiffRequest) (DiffResult, error) {
	if req.Limit < 1 || req.Limit > ChangePageMax {
		return DiffResult{}, &pagination.LimitError{Max: ChangePageMax}
	}
	var after *changeCursor
	if req.Cursor != "" {
		var c changeCursor
		if err := pagination.Decode(req.Cursor, &c); err != nil {
			return DiffResult{}, err
		}
		after = &c
	}
	if req.Kind != "" && !req.Kind.Valid() {
		return DiffResult{}, ErrInvalidChangeKind
	}
	var res DiffResult
	err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		if res.To, err = GetSnapshot(ctx, tx, req.ProjectID, req.To); err != nil {
			return err
		}
		from := req.From
		if from == uuid.Nil {
			if res.To.PreviousID == nil {
				return ErrNoPrevious
			}
			from = *res.To.PreviousID
		}
		if res.From, err = GetSnapshot(ctx, tx, req.ProjectID, from); err != nil {
			return err
		}
		var changes []Change
		if res.From.SetID != res.To.SetID {
			if changes, res.Stored, err = StoredDiff(ctx, tx, res.From.SetID, res.To.SetID); err != nil {
				return err
			}
			if !res.Stored {
				if changes, err = ComputeDiff(ctx, tx, h.cmp, res.From.SetID, res.To.SetID); err != nil {
					return err
				}
			}
		}
		res.Counts = countChanges(changes)
		var page []Change
		for _, ch := range changes {
			if (req.Kind == "" || ch.Kind == req.Kind) && (after == nil || after.before(ch)) {
				page = append(page, ch)
				if len(page) > req.Limit {
					break
				}
			}
		}
		res.Changes, err = pagination.Build(page, req.Limit, func(c Change) any { return cursorOf(c) })
		return err
	}, db.ReadOnly())
	if err != nil {
		return DiffResult{}, wrap("comparaison", err)
	}
	return res, nil
}

// SnapshotChoice est un instantané proposé dans le formulaire de comparaison.
type SnapshotChoice struct {
	ID        uuid.UUID
	RefID     uuid.UUID
	RefName   string
	RefKind   string
	Commit    string
	ScannedAt time.Time
}

// Choices renvoie, pour chaque référence du projet, ses perRef instantanés les plus
// récents, par référence puis du plus récent au plus ancien.
func (h *History) Choices(ctx context.Context, org tenant.OrgID, projectID uuid.UUID, perRef int) ([]SnapshotChoice, error) {
	var out []SnapshotChoice
	err := h.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT x.id, x.ref_id, r.name, r.kind, coalesce(x.commit_sha, ''), x.scanned_at FROM (
			    SELECT s.*, row_number() OVER (PARTITION BY s.ref_id ORDER BY s.scanned_at DESC, s.id DESC) AS n
			      FROM snapshots s WHERE s.project_id = $1) x
			  JOIN tracked_refs r ON r.org_id = x.org_id AND r.id = x.ref_id
			 WHERE x.n <= $2
			 ORDER BY r.kind, r.name, r.id, x.scanned_at DESC, x.id DESC`, projectID, perRef)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c SnapshotChoice
			if err := rows.Scan(&c.ID, &c.RefID, &c.RefName, &c.RefKind, &c.Commit, &c.ScannedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("instantanés à comparer", err)
}
