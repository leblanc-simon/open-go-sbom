package inventory

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/version"
)

// ChangeKind est la nature d'un changement entre deux ensembles d'inventaire.
type ChangeKind string

// Natures des changements, dans l'ordre d'affichage.
const (
	ChangeAdded      ChangeKind = "added"
	ChangeRemoved    ChangeKind = "removed"
	ChangeUpgraded   ChangeKind = "upgraded"
	ChangeDowngraded ChangeKind = "downgraded"
)

// ChangeKinds renvoie les natures de changement, dans l'ordre d'affichage.
func ChangeKinds() []ChangeKind {
	return []ChangeKind{ChangeAdded, ChangeRemoved, ChangeUpgraded, ChangeDowngraded}
}

func (k ChangeKind) rank() int { return slices.Index(ChangeKinds(), k) }

// Valid dit si k est une nature connue.
func (k ChangeKind) Valid() bool { return k.rank() >= 0 }

// DiffCounts compte les changements d'une différence par nature.
type DiffCounts struct {
	Added      int
	Removed    int
	Upgraded   int
	Downgraded int
}

// Total est le nombre de changements.
func (c DiffCounts) Total() int { return c.Added + c.Removed + c.Upgraded + c.Downgraded }

// Of renvoie le compte d'une nature.
func (c DiffCounts) Of(k ChangeKind) int {
	switch k {
	case ChangeAdded:
		return c.Added
	case ChangeRemoved:
		return c.Removed
	case ChangeUpgraded:
		return c.Upgraded
	case ChangeDowngraded:
		return c.Downgraded
	}
	return 0
}

func (c *DiffCounts) add(k ChangeKind) {
	switch k {
	case ChangeAdded:
		c.Added++
	case ChangeRemoved:
		c.Removed++
	case ChangeUpgraded:
		c.Upgraded++
	case ChangeDowngraded:
		c.Downgraded++
	}
}

// ChangeSide est un composant d'un côté d'un changement.
type ChangeSide struct {
	ComponentID uuid.UUID
	PURL        string
	Version     string
}

// Change est un changement entre deux ensembles : un ajout n'a que New, un retrait
// qu'Old ; une montée ou une descente relie deux versions d'un même purl_base.
type Change struct {
	Kind     ChangeKind
	PURLBase string
	Type     string
	Name     string
	Old      *ChangeSide
	New      *ChangeSide
	// Approximate : versions incomparables dans leur écosystème ; le sens de la montée
	// ou de la descente vient de l'ordre des chaînes.
	Approximate bool
}

// sideItem est un composant présent d'un seul côté d'une différence.
type sideItem struct {
	ID       uuid.UUID
	PURL     string
	PURLBase string
	Type     string
	Name     string
	Version  string
}

func (s sideItem) side() *ChangeSide {
	return &ChangeSide{ComponentID: s.ID, PURL: s.PURL, Version: s.Version}
}

// compareVersions compare deux versions d'un composant de type purlType selon son
// écosystème, puis en semver générique ; à défaut, ou pour deux chaînes différentes que
// l'écosystème juge égales (« 1.0 » et « 1.0.0 »), selon l'ordre des chaînes, et le
// résultat est approché.
func compareVersions(c version.Comparer, purlType, a, b string) (int, bool) {
	if a == b {
		return 0, false
	}
	for _, s := range []version.Scheme{version.ForPURLType(purlType), version.SchemeSemver} {
		if r, err := c.Compare(s, a, b); err == nil && r != 0 {
			return cmp.Compare(r, 0), false
		}
	}
	return strings.Compare(a, b), true
}

// classify range les composants retirés et ajoutés en changements. Pour un même
// purl_base, les versions retirées et ajoutées sont triées puis appariées dans l'ordre :
// chaque couple est une montée ou une descente, le reste des ajouts et des retraits. Une
// version présente des deux côtés (qualificatifs changés : architecture, distribution)
// n'est ni une montée ni une descente : elle reste un retrait et un ajout.
func classify(c version.Comparer, removed, added []sideItem) []Change {
	type group struct{ removed, added []sideItem }
	groups := map[string]*group{}
	get := func(base string) *group {
		g, ok := groups[base]
		if !ok {
			g = &group{}
			groups[base] = g
		}
		return g
	}
	for _, it := range removed {
		g := get(it.PURLBase)
		g.removed = append(g.removed, it)
	}
	for _, it := range added {
		g := get(it.PURLBase)
		g.added = append(g.added, it)
	}
	var out []Change
	for base, g := range groups {
		byVersion := func(a, b sideItem) int {
			r, _ := compareVersions(c, a.Type, a.Version, b.Version)
			if r != 0 {
				return r
			}
			return strings.Compare(a.PURL, b.PURL)
		}
		slices.SortFunc(g.removed, byVersion)
		slices.SortFunc(g.added, byVersion)
		oldVersions, newVersions := map[string]bool{}, map[string]bool{}
		for _, it := range g.removed {
			oldVersions[it.Version] = true
		}
		for _, it := range g.added {
			newVersions[it.Version] = true
		}
		var pairR, pairA []sideItem
		for _, it := range g.removed {
			if newVersions[it.Version] {
				out = append(out, Change{Kind: ChangeRemoved, PURLBase: base, Type: it.Type, Name: it.Name, Old: it.side()})
				continue
			}
			pairR = append(pairR, it)
		}
		for _, it := range g.added {
			if oldVersions[it.Version] {
				out = append(out, Change{Kind: ChangeAdded, PURLBase: base, Type: it.Type, Name: it.Name, New: it.side()})
				continue
			}
			pairA = append(pairA, it)
		}
		n := min(len(pairR), len(pairA))
		for i := range n {
			o, a := pairR[i], pairA[i]
			r, approx := compareVersions(c, a.Type, o.Version, a.Version)
			kind := ChangeUpgraded
			if r > 0 {
				kind = ChangeDowngraded
			}
			out = append(out, Change{Kind: kind, PURLBase: base, Type: a.Type, Name: a.Name, Old: o.side(), New: a.side(), Approximate: approx})
		}
		for _, it := range pairR[n:] {
			out = append(out, Change{Kind: ChangeRemoved, PURLBase: base, Type: it.Type, Name: it.Name, Old: it.side()})
		}
		for _, it := range pairA[n:] {
			out = append(out, Change{Kind: ChangeAdded, PURLBase: base, Type: it.Type, Name: it.Name, New: it.side()})
		}
	}
	slices.SortFunc(out, compareChanges)
	return out
}

func sidePURL(s *ChangeSide) string {
	if s == nil {
		return ""
	}
	return s.PURL
}

// compareChanges ordonne les changements : nature, purl_base, ancien puis nouveau purl.
func compareChanges(a, b Change) int {
	return cmp.Or(cmp.Compare(a.Kind.rank(), b.Kind.rank()), strings.Compare(a.PURLBase, b.PURLBase),
		strings.Compare(sidePURL(a.Old), sidePURL(b.Old)), strings.Compare(sidePURL(a.New), sidePURL(b.New)))
}

func countChanges(cs []Change) DiffCounts {
	var c DiffCounts
	for _, ch := range cs {
		c.add(ch.Kind)
	}
	return c
}

// changedItems lit les composants présents dans un seul des deux ensembles : ceux de from
// seulement (retirés ou anciennes versions), ceux de to seulement (ajoutés ou nouvelles
// versions).
func changedItems(ctx context.Context, tx *db.OrgTx, from, to uuid.UUID) (removed, added []sideItem, err error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT f.component_id IS NULL, c.id, c.purl, c.purl_base, c.type, c.name, c.version
		  FROM (SELECT component_id FROM component_set_items WHERE set_id = $1) f
		  FULL JOIN (SELECT component_id FROM component_set_items WHERE set_id = $2) t ON t.component_id = f.component_id
		  JOIN components c ON c.id = coalesce(f.component_id, t.component_id)
		 WHERE f.component_id IS NULL OR t.component_id IS NULL`, from, to)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var isNew bool
		var it sideItem
		if err := rows.Scan(&isNew, &it.ID, &it.PURL, &it.PURLBase, &it.Type, &it.Name, &it.Version); err != nil {
			return nil, nil, err
		}
		if isNew {
			added = append(added, it)
		} else {
			removed = append(removed, it)
		}
	}
	return removed, added, rows.Err()
}

// ComputeDiff calcule la différence entre deux ensembles d'inventaire de l'organisation,
// sans la stocker.
func ComputeDiff(ctx context.Context, tx *db.OrgTx, c version.Comparer, from, to uuid.UUID) ([]Change, error) {
	if from == to {
		return nil, nil
	}
	removed, added, err := changedItems(ctx, tx, from, to)
	if err != nil {
		return nil, wrap("différence", err)
	}
	return classify(c, removed, added), nil
}

// storeDiff enregistre une différence calculée ; une différence déjà enregistrée
// (calcul concurrent) est laissée telle quelle.
func storeDiff(ctx context.Context, tx *db.OrgTx, from, to uuid.UUID, changes []Change, now time.Time) error {
	counts := countChanges(changes)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO set_diffs (org_id, from_set_id, to_set_id, added_count, removed_count, upgraded_count, downgraded_count, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`,
		tx.OrgID(), from, to, counts.Added, counts.Removed, counts.Upgraded, counts.Downgraded, now)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return err
	}
	for start := 0; start < len(changes); start += chunk {
		part := changes[start:min(start+chunk, len(changes))]
		kinds, bases, olds, news, approx := make([]string, len(part)), make([]string, len(part)), make([]string, len(part)),
			make([]string, len(part)), make([]string, len(part))
		for i, ch := range part {
			kinds[i], bases[i], approx[i] = string(ch.Kind), ch.PURLBase, fmt.Sprint(ch.Approximate)
			if ch.Old != nil {
				olds[i] = ch.Old.ComponentID.String()
			}
			if ch.New != nil {
				news[i] = ch.New.ComponentID.String()
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO set_diff_items (org_id, from_set_id, to_set_id, kind, purl_base, old_component_id, new_component_id, approximate)
			SELECT $1, $2, $3, u.kind, u.base, NULLIF(u.old, '')::uuid, NULLIF(u.new, '')::uuid, u.approx::boolean
			  FROM unnest($4::text[], $5::text[], $6::text[], $7::text[], $8::text[]) AS u(kind, base, old, new, approx)`,
			tx.OrgID(), from, to, kinds, bases, olds, news, approx); err != nil {
			return err
		}
	}
	return nil
}

// StoredDiff lit une différence enregistrée ; faux si elle ne l'est pas (encore).
func StoredDiff(ctx context.Context, tx *db.OrgTx, from, to uuid.UUID) ([]Change, bool, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM set_diffs WHERE from_set_id = $1 AND to_set_id = $2)`,
		from, to).Scan(&exists); err != nil || !exists {
		return nil, false, wrap("différence enregistrée", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT i.kind, i.purl_base, i.approximate, coalesce(n.type, o.type), coalesce(n.name, o.name),
		       o.id, coalesce(o.purl, ''), coalesce(o.version, ''), n.id, coalesce(n.purl, ''), coalesce(n.version, '')
		  FROM set_diff_items i
		  LEFT JOIN components o ON o.org_id = i.org_id AND o.id = i.old_component_id
		  LEFT JOIN components n ON n.org_id = i.org_id AND n.id = i.new_component_id
		 WHERE i.from_set_id = $1 AND i.to_set_id = $2`, from, to)
	if err != nil {
		return nil, false, wrap("différence enregistrée", err)
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var ch Change
		var kind string
		var oldID, newID uuid.NullUUID
		var old, nw ChangeSide
		if err := rows.Scan(&kind, &ch.PURLBase, &ch.Approximate, &ch.Type, &ch.Name, &oldID, &old.PURL, &old.Version,
			&newID, &nw.PURL, &nw.Version); err != nil {
			return nil, false, wrap("différence enregistrée", err)
		}
		ch.Kind = ChangeKind(kind)
		if oldID.Valid {
			old.ComponentID = oldID.UUID
			ch.Old = &old
		}
		if newID.Valid {
			nw.ComponentID = newID.UUID
			ch.New = &nw
		}
		out = append(out, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, false, wrap("différence enregistrée", err)
	}
	slices.SortFunc(out, compareChanges)
	return out, true, nil
}

// missingDiffs renvoie les couples d'ensembles d'instantanés consécutifs (date de scan,
// puis identifiant) dont la différence n'est pas enregistrée : d'une référence, ou de
// toutes si refID est nul.
func missingDiffs(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) ([][2]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT x.prev, x.set_id FROM (
		    SELECT set_id, lag(set_id) OVER (PARTITION BY ref_id ORDER BY scanned_at, id) AS prev
		      FROM snapshots WHERE $1::uuid IS NULL OR ref_id = $1) x
		 WHERE x.prev IS NOT NULL AND x.prev <> x.set_id
		   AND NOT EXISTS (SELECT 1 FROM set_diffs d WHERE d.from_set_id = x.prev AND d.to_set_id = x.set_id)
		 ORDER BY 1, 2`, nullUUID(refID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]uuid.UUID
	for rows.Next() {
		var p [2]uuid.UUID
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
