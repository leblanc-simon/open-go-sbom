package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/org"
	"leblanc.io/lotor/internal/tenant"
)

// deadJobsPage borne une page de l'écran des traitements en échec.
const deadJobsPage = 50

// deadJobRow est un job mort prêt à afficher. Org est vide pour un job d'instance ;
// OrgMissing indique une organisation disparue depuis.
type deadJobRow struct {
	jobs.DeadJob
	Org        *org.Organization
	OrgMissing bool
	Created    *stamp
	Finished   *stamp
}

type jobsView struct {
	adminPage
	Counts     jobs.Counts
	Jobs       []deadJobRow
	NextCursor string
}

// adminJobs liste les traitements en échec (jobs morts) : relance ou abandon, chacun
// journalisé.
func (id *identity) adminJobs(w http.ResponseWriter, r *http.Request) {
	id.jobsPage(w, r, http.StatusOK, formError{})
}

func (id *identity) jobsPage(w http.ResponseWriter, r *http.Request, status int, fe formError) {
	base, err := id.adminPage(r, "admin_jobs.title", "jobs")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	base.Error = fe
	ctx := r.Context()
	counts, err := jobs.CountJobs(ctx, id.Pool.DB())
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	page, err := jobs.ListDead(ctx, id.Pool.DB(), r.URL.Query().Get("cursor"), deadJobsPage)
	if err != nil {
		e, ok := validationOf(err)
		if !ok {
			id.serverError(w, r, err)
			return
		}
		base.Error, status = e, http.StatusBadRequest
	}
	view := &jobsView{adminPage: base, Counts: counts, NextCursor: page.NextCursor}
	// Les organisations des jobs de la page (une lecture par organisation, sous sa RLS).
	orgs := map[tenant.OrgID]*org.Organization{}
	for _, d := range page.Items {
		row := deadJobRow{DeadJob: d, Created: stampAt(d.CreatedAt), Finished: stampAt(d.FinishedAt)}
		if !d.OrgID.IsZero() {
			o, seen := orgs[d.OrgID]
			if !seen {
				got, err := id.Orgs.Get(ctx, d.OrgID)
				switch {
				case err == nil:
					o = &got
				case errors.Is(err, org.ErrNotFound):
				default:
					id.serverError(w, r, err)
					return
				}
				orgs[d.OrgID] = o
			}
			row.Org, row.OrgMissing = o, o == nil
		}
		view.Jobs = append(view.Jobs, row)
	}
	id.rd.Render(w, r, status, "admin/jobs", view)
}

// jobAction relance ou abandonne un job mort, dans la même transaction que son entrée
// d'audit.
func (id *identity) jobAction(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	var apply func(*db.Tx) error
	action, done := audit.JobRetried, "job_retried"
	switch chi.URLParam(r, "action") {
	case "retry":
		apply = func(tx *db.Tx) error { return jobs.Retry(r.Context(), tx, jobID) }
	case "discard":
		apply = func(tx *db.Tx) error { return jobs.Discard(r.Context(), tx, jobID) }
		action, done = audit.JobDiscarded, "job_discarded"
	default:
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	ctx := r.Context()
	err = id.Pool.InTx(ctx, func(tx *db.Tx) error {
		d, err := jobs.GetDead(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if err := apply(tx); err != nil {
			return err
		}
		details := map[string]string{"attempts": strconv.Itoa(d.Attempts)}
		if !d.OrgID.IsZero() {
			details["org"] = d.OrgID.String()
		}
		return audit.RecordInstance(ctx, tx, id.actor(r), audit.Event{Action: action, TargetType: "job",
			TargetID: d.ID.String(), TargetLabel: d.Kind, Details: details})
	})
	if errors.Is(err, jobs.ErrNotFound) {
		// Déjà relancé ou abandonné (double envoi, autre administrateur).
		id.jobsPage(w, r, http.StatusNotFound, formError{Key: "admin_jobs.not_found"})
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, "/admin/jobs", done)
}
