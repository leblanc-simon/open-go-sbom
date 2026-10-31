package web

import (
	"errors"
	"net/http"
	"path"
	"time"

	"leblanc.io/lotor/internal/vuln"
)

// VulnDBOptions règle l'écran de la base de vulnérabilités.
type VulnDBOptions struct {
	// MaxAge : au-delà, l'administration de l'instance affiche une alerte.
	MaxAge     time.Duration
	Offline    bool
	ListingURL string
	// SyncInterval est la période de synchronisation des instances worker : une instance
	// sans nouvelles depuis plusieurs périodes est signalée.
	SyncInterval time.Duration
	// MaxArchive borne une archive téléversée (vulndb.max_archive_mib).
	MaxArchive int64
	// UploadTimeout borne la durée d'un téléversement (vulndb.download_timeout).
	UploadTimeout time.Duration
}

// instanceSilentAfter : une instance worker qui n'a rien rapporté depuis cette durée est
// signalée « sans nouvelles ». Une première installation de la base (plusieurs minutes)
// ne doit pas suffire à la signaler.
func (o VulnDBOptions) instanceSilentAfter() time.Duration {
	return max(3*o.SyncInterval, 15*time.Minute)
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

// age est une durée affichée en heures sous deux jours, en jours au-delà.
type age struct {
	Hours, Days int
}

func ageOf(d time.Duration) age {
	if d < 0 {
		d = 0
	}
	if d < 48*time.Hour {
		return age{Hours: int(d / time.Hour)}
	}
	return age{Days: int(d / (24 * time.Hour))}
}

// instanceRow est l'état d'une instance worker. State : current (base cible chargée),
// behind (autre base), none (aucune base), silent (sans nouvelles).
type instanceRow struct {
	Name      string
	State     string
	Built     *stamp
	Age       *age
	Loaded    *stamp
	Seen      *stamp
	SyncError string
}

type importRow struct {
	vuln.Import
	SizeMiB  float64
	Created  *stamp
	Finished *stamp
}

type vulnDBView struct {
	adminPage
	Target      *archiveRow
	TargetAge   age
	LastCheck   *stamp
	CheckError  string
	Archives    []archiveRow
	Purgeable   int
	Instances   []instanceRow
	Imports     []importRow
	Importing   bool
	MaxArchive  float64 // Mio
	Offline     bool
	ListingURL  string
	MaxAgeHours int
}

// archivesShown et importsShown bornent les listes de l'écran.
const (
	archivesShown = 10
	importsShown  = 5
)

func archiveRowOf(a vuln.Archive) archiveRow {
	return archiveRow{Archive: a, Built: stampAt(a.Built), Created: stampAt(a.CreatedAt), SizeMiB: mib(a.Size),
		Targeted: stampOf(a.TargetedAt)}
}

func mib(n int64) float64 { return float64(n) / (1 << 20) }

// vulnDB est l'état de la base de vulnérabilités commune : cible et son âge, dernière
// vérification, version chargée par chaque instance worker, archives stockées (purge des
// anciennes) et import manuel d'une archive (site isolé).
func (id *identity) vulnDB(w http.ResponseWriter, r *http.Request) {
	id.vulnDBPage(w, r, http.StatusOK, formError{})
}

func (id *identity) vulnDBPage(w http.ResponseWriter, r *http.Request, status int, fe formError) {
	page, err := id.adminPage(r, "admin_vulndb.title", "vulndb")
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	page.Error = fe
	ctx := r.Context()
	q := id.Pool.DB()
	st, err := vuln.ReadState(ctx, q)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	archives, err := vuln.ListArchives(ctx, q, archivesShown)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	instances, err := vuln.ListInstances(ctx, q)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	imports, err := vuln.ListImports(ctx, q, importsShown)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	now := id.Agents.Now()
	view := &vulnDBView{adminPage: page, LastCheck: stampOf(st.LastCheckAt), CheckError: st.LastCheckError,
		MaxArchive: mib(id.VulnDB.MaxArchive), Offline: id.VulnDB.Offline, ListingURL: id.VulnDB.ListingURL,
		MaxAgeHours: int(id.VulnDB.MaxAge.Hours())}
	if st.Target != nil {
		t := archiveRowOf(*st.Target)
		view.Target, view.TargetAge = &t, ageOf(now.Sub(st.Target.Built))
	}
	for _, a := range archives {
		view.Archives = append(view.Archives, archiveRowOf(a))
		if !a.IsTarget {
			view.Purgeable++
		}
	}
	for _, in := range instances {
		view.Instances = append(view.Instances, id.instanceRowOf(in, st.Target, now))
	}
	for _, imp := range imports {
		view.Imports = append(view.Imports, importRow{Import: imp, SizeMiB: mib(imp.Size), Created: stampAt(imp.CreatedAt),
			Finished: stampOf(imp.FinishedAt)})
		if imp.Status == vuln.ImportUploading || imp.Status == vuln.ImportQueued {
			view.Importing = true
		}
	}
	id.rd.Render(w, r, status, "admin/vulndb", view)
}

func (id *identity) instanceRowOf(in vuln.Instance, target *vuln.Archive, now time.Time) instanceRow {
	row := instanceRow{Name: in.Name, Seen: stampAt(in.SeenAt), Loaded: stampOf(in.LoadedAt), SyncError: in.SyncError}
	switch {
	case now.Sub(in.SeenAt) > id.VulnDB.instanceSilentAfter():
		row.State = "silent"
	case in.Loaded.IsZero():
		row.State = "none"
	case target != nil && in.Loaded.ArchiveID == target.ID:
		row.State = "current"
	default:
		row.State = "behind"
	}
	if !in.Loaded.IsZero() {
		a := ageOf(now.Sub(in.Loaded.Built))
		row.Built, row.Age = stampAt(in.Loaded.Built), &a
	}
	return row
}

// importVulnDB reçoit une archive de la base (formulaire multipart lu en flux, voir
// uploadGate), la range en base et met en file son installation par une instance worker
// (job vulndb.import) : l'installation prend plusieurs minutes.
func (id *identity) importVulnDB(w http.ResponseWriter, r *http.Request) {
	mr := uploadReader(r)
	if mr == nil {
		id.vulnDBPage(w, r, http.StatusBadRequest, formError{Key: "admin_vulndb.import_missing", Field: "archive"})
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "archive" || part.FileName() == "" {
		id.vulnDBPage(w, r, http.StatusBadRequest, formError{Key: "admin_vulndb.import_missing", Field: "archive"})
		return
	}
	_, err = vuln.Upload(r.Context(), id.Pool, part, vuln.UploadOptions{
		MaxSize: id.VulnDB.MaxArchive, StaleAfter: id.VulnDB.UploadTimeout, FileName: path.Base(part.FileName()),
		Actor: id.actor(r), Now: id.Agents.Now,
	})
	var tooBig *http.MaxBytesError
	switch {
	case err == nil:
		redirectDone(w, r, "/admin/vulndb", "vulndb_import_queued")
	case errors.Is(err, vuln.ErrTooLarge), errors.As(err, &tooBig):
		id.vulnDBPage(w, r, http.StatusRequestEntityTooLarge, formError{Key: "admin_vulndb.import_too_large", Field: "archive"})
	case errors.Is(err, vuln.ErrImportInProgress):
		id.vulnDBPage(w, r, http.StatusConflict, formError{Key: "admin_vulndb.import_in_progress", Field: "archive"})
	case errors.Is(err, vuln.ErrInvalidArchive):
		id.vulnDBPage(w, r, http.StatusUnprocessableEntity, formError{Key: "admin_vulndb.import_empty", Field: "archive"})
	default:
		id.serverError(w, r, err)
	}
}

// purgeVulnDB supprime les archives qui ne sont pas la cible, après confirmation.
func (id *identity) purgeVulnDB(w http.ResponseWriter, r *http.Request) {
	if !id.parseForm(w, r) {
		return
	}
	if r.PostForm.Get("confirm") != "on" {
		id.vulnDBPage(w, r, http.StatusUnprocessableEntity, formError{Key: "admin_vulndb.purge_confirm_required", Field: "confirm"})
		return
	}
	if _, err := vuln.PurgeArchives(r.Context(), id.Pool, id.actor(r)); err != nil {
		id.serverError(w, r, err)
		return
	}
	redirectDone(w, r, "/admin/vulndb", "vulndb_purged")
}
