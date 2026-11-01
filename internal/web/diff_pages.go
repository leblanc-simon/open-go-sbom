package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/tenant"
)

// Tailles de l'écran de comparaison.
const (
	changePageSize = 100
	// compareChoices : instantanés de chaque référence proposés dans le formulaire.
	compareChoices = 50
)

// changeCounts est le résumé des changements d'un instantané depuis son précédent, dans
// la frise.
type changeCounts struct {
	inventory.DiffCounts
	Total int
}

func changeCountsOf(c *inventory.DiffCounts) *changeCounts {
	if c == nil {
		return nil
	}
	return &changeCounts{DiffCounts: *c, Total: c.Total()}
}

// choiceGroup est une référence et ses instantanés dans un menu de comparaison.
type choiceGroup struct {
	Label   string
	Options []option
}

// compareForm est le formulaire « Comparer deux instantanés ».
type compareForm struct {
	Action string
	From   []choiceGroup
	To     []choiceGroup
}

// compareFormOf construit le formulaire : de (le précédent par défaut) et vers, parmi les
// instantanés récents de chaque référence du projet.
func compareFormOf(action string, choices []inventory.SnapshotChoice, from, to uuid.UUID) *compareForm {
	if len(choices) < 2 {
		return nil
	}
	f := &compareForm{Action: action}
	f.From = append(f.From, choiceGroup{Options: []option{{Value: "", LabelKey: "compare.previous", Selected: from == uuid.Nil}}})
	var groupFrom, groupTo *choiceGroup
	var ref uuid.UUID
	for i, c := range choices {
		if i == 0 || c.RefID != ref {
			ref = c.RefID
			f.From = append(f.From, choiceGroup{Label: c.RefName})
			f.To = append(f.To, choiceGroup{Label: c.RefName})
			groupFrom, groupTo = &f.From[len(f.From)-1], &f.To[len(f.To)-1]
		}
		label := stampAt(c.ScannedAt).Display
		if c.Commit != "" {
			label += " · " + shortCommit(c.Commit)
		}
		selectedTo := c.ID == to || (to == uuid.Nil && i == 0)
		groupFrom.Options = append(groupFrom.Options, option{Value: c.ID.String(), Label: label, Selected: c.ID == from})
		groupTo.Options = append(groupTo.Options, option{Value: c.ID.String(), Label: label, Selected: selectedTo})
	}
	return f
}

// kindTile est une nature de changement, son compte et le lien qui filtre la liste.
type kindTile struct {
	Kind     string
	LabelKey string
	Count    int
	Href     template.URL
	Selected bool
}

// changeRow est un changement prêt à afficher.
type changeRow struct {
	Kind        string
	Name        string
	Type        string
	PURLBase    string
	OldVersion  string
	NewVersion  string
	OldHref     string
	NewHref     string
	Approximate bool
}

type compareSide struct {
	Row     snapshotRow
	RefName string
	RefKind string
}

type compareView struct {
	render.Page
	Base    string
	Project projectRow
	Tabs    []projectTab
	Form    *compareForm
	// NoPrevious : l'instantané demandé est le premier de sa référence.
	NoPrevious bool
	From       compareSide
	To         compareSide
	SwapHref   template.URL
	Total      int
	Tiles      []kindTile
	AllHref    template.URL
	Kind       string
	Changes    []changeRow
	NextHref   template.URL
	Effect     effectView
}

// effectView est l'effet sur la sécurité : constats résolus, puis introduits.
type effectView struct {
	Tables  []effectTable
	Pending bool
}

type effectTable struct {
	ID       string
	TitleKey string
	EmptyKey string
	Rows     []findingRow
	Total    int
	Max      int
}

func compareQuery(from, to uuid.UUID, kind, cursor string) template.URL {
	q := url.Values{"to": {to.String()}}
	if from != uuid.Nil {
		q.Set("from", from.String())
	}
	if kind != "" {
		q.Set("kind", kind)
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	// Requête construite ici par url.Values : sûre comme URL.
	return template.URL("?" + q.Encode())
}

// parseOptionalID lit un identifiant facultatif ; faux s'il est présent et illisible.
func parseOptionalID(raw string) (uuid.UUID, bool) {
	if raw == "" {
		return uuid.Nil, true
	}
	id, err := uuid.Parse(raw)
	return id, err == nil
}

// compare rend la comparaison de deux instantanés du projet : changements par nature et
// effet sur la sécurité (constats introduits et résolus).
func (id *identity) compare(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	acc := access(r)
	ctx := r.Context()
	q := r.URL.Query()
	from, okFrom := parseOptionalID(q.Get("from"))
	to, okTo := parseOptionalID(q.Get("to"))
	kind := inventory.ChangeKind(q.Get("kind"))
	if !okFrom || !okTo || to == uuid.Nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if kind != "" && !kind.Valid() {
		id.rd.Error(w, r, http.StatusBadRequest)
		return
	}
	base := orgBase(acc) + "/projects/" + p.Slug
	view := &compareView{
		Page: render.Page{TitleKey: "compare.title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "snapshots"), Kind: string(kind),
	}
	res, err := id.History.Diff(ctx, acc.Org, inventory.DiffRequest{ProjectID: p.ID, From: from, To: to, Kind: kind,
		Cursor: q.Get("cursor"), Limit: changePageSize})
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		id.rd.Error(w, r, http.StatusNotFound)
		return
	case errors.Is(err, inventory.ErrNoPrevious):
		view.NoPrevious = true
	case isPaginationError(err):
		id.rd.Error(w, r, http.StatusBadRequest)
		return
	case err != nil:
		id.serverError(w, r, err)
		return
	}
	choices, err := id.History.Choices(ctx, acc.Org, p.ID, compareChoices)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view.Form = compareFormOf(base+"/compare", choices, from, to)
	if view.NoPrevious {
		id.rd.Render(w, r, http.StatusOK, "projects/compare", view)
		return
	}
	if err := id.fillCompare(r, acc, p, base, from, res, view); err != nil {
		id.serverError(w, r, err)
		return
	}
	id.rd.Render(w, r, http.StatusOK, "projects/compare", view)
}

func (id *identity) fillCompare(r *http.Request, acc tenant.Access, p project.Project, base string, from uuid.UUID,
	res inventory.DiffResult, view *compareView) error {
	view.From = compareSide{Row: id.snapshotRow(base, res.From), RefName: res.From.RefName, RefKind: res.From.RefKind}
	view.To = compareSide{Row: id.snapshotRow(base, res.To), RefName: res.To.RefName, RefKind: res.To.RefKind}
	view.SwapHref = compareQuery(res.To.ID, res.From.ID, "", "")
	view.Total = res.Counts.Total()
	view.AllHref = compareQuery(from, res.To.ID, "", "")
	for _, k := range inventory.ChangeKinds() {
		view.Tiles = append(view.Tiles, kindTile{Kind: string(k), LabelKey: "compare.kind_" + string(k), Count: res.Counts.Of(k),
			Href: compareQuery(from, res.To.ID, string(k), ""), Selected: view.Kind == string(k)})
	}
	components := orgBase(acc) + "/components/"
	for _, c := range res.Changes.Items {
		row := changeRow{Kind: string(c.Kind), Name: c.Name, Type: c.Type, PURLBase: c.PURLBase, Approximate: c.Approximate}
		if c.Old != nil {
			row.OldVersion, row.OldHref = c.Old.Version, components+c.Old.ComponentID.String()
		}
		if c.New != nil {
			row.NewVersion, row.NewHref = c.New.Version, components+c.New.ComponentID.String()
		}
		view.Changes = append(view.Changes, row)
	}
	if res.Changes.NextCursor != "" {
		view.NextHref = compareQuery(from, res.To.ID, view.Kind, res.Changes.NextCursor)
	}
	eff, err := id.Findings.Effect(r.Context(), acc.Org,
		finding.EffectSide{SnapshotID: res.From.ID, RefID: res.From.RefID, SetID: res.From.SetID},
		finding.EffectSide{SnapshotID: res.To.ID, RefID: res.To.RefID, SetID: res.To.SetID})
	if err != nil {
		return err
	}
	rows := func(fs []finding.Row) []findingRow {
		var out []findingRow
		for _, f := range fs {
			out = append(out, id.findingRow(orgBase(acc), f))
		}
		return out
	}
	view.Effect = effectView{Pending: eff.Pending, Tables: []effectTable{
		{ID: "effect-resolved", TitleKey: "compare.resolved_title", EmptyKey: "compare.none_resolved", Rows: rows(eff.Resolved),
			Total: eff.ResolvedTotal, Max: finding.EffectMax},
		{ID: "effect-introduced", TitleKey: "compare.introduced_title", EmptyKey: "compare.none_introduced", Rows: rows(eff.Introduced),
			Total: eff.IntroducedTotal, Max: finding.EffectMax},
	}}
	return nil
}
