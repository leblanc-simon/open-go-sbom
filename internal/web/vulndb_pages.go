package web

import (
	"net/http"
	"time"

	"leblanc.io/open-go-sbom/internal/vuln"
)

// VulnDBOptions règle l'écran de la base de vulnérabilités.
type VulnDBOptions struct {
	// MaxAge : au-delà, l'administration de l'instance affiche une alerte.
	MaxAge     time.Duration
	Offline    bool
	ListingURL string
}

// vulnDBAlert est l'alerte d'âge de la base, affichée sur chaque page d'administration.
type vulnDBAlert struct {
	Missing bool
	Days    int
	Built   *stamp
}

func (id *identity) vulnDBAlert(st vuln.State) *vulnDBAlert {
	now := id.Agents.Now()
	if !st.Stale(now, id.VulnDB.MaxAge) {
		return nil
	}
	if st.Target == nil {
		return &vulnDBAlert{Missing: true}
	}
	return &vulnDBAlert{Days: int(now.Sub(st.Target.Built) / (24 * time.Hour)), Built: stampAt(st.Target.Built)}
}

type archiveRow struct {
	vuln.Archive
	Built    *stamp
	Created  *stamp
	SizeMiB  float64
	Targeted *stamp
}

type vulnDBView struct {
	adminPage
	Target      *archiveRow
	LastCheck   *stamp
	CheckError  string
	Archives    []archiveRow
	Offline     bool
	ListingURL  string
	MaxAgeHours int
}

// archivesShown borne la liste des archives de l'écran.
const archivesShown = 10

func archiveRowOf(a vuln.Archive) archiveRow {
	return archiveRow{Archive: a, Built: stampAt(a.Built), Created: stampAt(a.CreatedAt), SizeMiB: float64(a.Size) / (1 << 20),
		Targeted: stampOf(a.TargetedAt)}
}

// vulnDB est l'état de la base de vulnérabilités commune : cible, dernière vérification,
// archives stockées. L'import manuel (site isolé) arrive en T11.
func (id *identity) vulnDB(w http.ResponseWriter, r *http.Request) {
	page, err := id.adminPage(r, "admin_vulndb.title", "vulndb")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	ctx := r.Context()
	st, err := vuln.ReadState(ctx, id.Pool.DB())
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	archives, err := vuln.ListArchives(ctx, id.Pool.DB(), archivesShown)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &vulnDBView{adminPage: page, LastCheck: stampOf(st.LastCheckAt), CheckError: st.LastCheckError,
		Offline: id.VulnDB.Offline, ListingURL: id.VulnDB.ListingURL, MaxAgeHours: int(id.VulnDB.MaxAge.Hours())}
	if st.Target != nil {
		t := archiveRowOf(*st.Target)
		view.Target = &t
	}
	for _, a := range archives {
		view.Archives = append(view.Archives, archiveRowOf(a))
	}
	id.rd.Render(w, r, http.StatusOK, "admin/vulndb", view)
}
