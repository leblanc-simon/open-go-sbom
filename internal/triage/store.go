package triage

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
)

// pair est un couple (famille de composants, vulnérabilité) : toutes les décisions qui
// peuvent concerner un constat partagent son couple.
type pair struct {
	PURLBase string
	VulnID   string
}

func comparePairs(a, b pair) int {
	if c := strings.Compare(a.PURLBase, b.PURLBase); c != 0 {
		return c
	}
	return strings.Compare(a.VulnID, b.VulnID)
}

// lock sérialise les écritures du triage d'une organisation. Une décision (exclusif) et
// la classification des constats créés par une analyse (partagé) ne se croisent jamais :
// sans ce verrou, un constat inséré par une analyse en cours échapperait au recalcul
// d'une décision validée entre-temps, et garderait « à analyser » (ADR 0035).
func lock(ctx context.Context, tx *db.OrgTx, exclusive bool) error {
	fn := "pg_advisory_xact_lock_shared"
	if exclusive {
		fn = "pg_advisory_xact_lock"
	}
	_, err := tx.ExecContext(ctx, `SELECT `+fn+`(hashtextextended('lotor.triage:' || $1::text, 0))`, tx.OrgID().String())
	return err
}

const decisionColumns = `id, scope, project_id, vuln_id, coalesce(purl, ''), purl_base, coalesce(vers, ''), action,
	coalesce(status, ''), coalesce(justification, ''), comment, expires_on, coalesce(author_user_id, 0), author_label,
	expires_id, created_at`

func scanDecision(s interface{ Scan(...any) error }) (Decision, error) {
	var d Decision
	var scope, action, status, just string
	var project, expires uuid.NullUUID
	var until sql.NullTime
	err := s.Scan(&d.ID, &scope, &project, &d.VulnID, &d.PURL, &d.PURLBase, &d.Vers, &action, &status, &just, &d.Comment,
		&until, &d.AuthorUserID, &d.AuthorLabel, &expires, &d.CreatedAt)
	if err != nil {
		return Decision{}, err
	}
	d.Scope, d.Action, d.Status, d.Justification = Scope(scope), Action(action), Status(status), Justification(just)
	d.ProjectID, d.ExpiresID = project.UUID, expires.UUID
	if until.Valid {
		t := time.Date(until.Time.Year(), until.Time.Month(), until.Time.Day(), 0, 0, 0, 0, time.UTC)
		d.ExpiresOn = &t
	}
	d.CreatedAt = d.CreatedAt.UTC()
	return d, nil
}

func queryDecisions(ctx context.Context, tx *db.OrgTx, query string, args ...any) ([]Decision, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// decisionsFor renvoie le journal des décisions des couples, groupé par couple.
func decisionsFor(ctx context.Context, tx *db.OrgTx, pairs []pair) (map[pair][]Decision, error) {
	out := map[pair][]Decision{}
	if len(pairs) == 0 {
		return out, nil
	}
	bases, vulns := splitPairs(pairs)
	ds, err := queryDecisions(ctx, tx, `SELECT `+decisionColumns+` FROM triage_decisions
		 WHERE (purl_base, vuln_id) IN (SELECT * FROM unnest($1::text[], $2::text[]))`, bases, vulns)
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		p := pair{d.PURLBase, d.VulnID}
		out[p] = append(out[p], d)
	}
	return out, nil
}

func splitPairs(pairs []pair) ([]string, []string) {
	bases, vulns := make([]string, len(pairs)), make([]string, len(pairs))
	for i, p := range pairs {
		bases[i], vulns[i] = p.PURLBase, p.VulnID
	}
	return bases, vulns
}

// getDecision lit une décision ; sql.ErrNoRows si elle n'existe pas.
func getDecision(ctx context.Context, tx *db.OrgTx, id uuid.UUID) (Decision, error) {
	return scanDecision(tx.QueryRowContext(ctx, `SELECT `+decisionColumns+` FROM triage_decisions WHERE id = $1`, id))
}

// insertDecisions ajoute des décisions au journal.
func insertDecisions(ctx context.Context, tx *db.OrgTx, ds []Decision) error {
	for start := 0; start < len(ds); start += writeChunk {
		part := ds[start:min(start+writeChunk, len(ds))]
		cols := make([][]string, 15)
		for _, d := range part {
			until := ""
			if d.ExpiresOn != nil {
				until = d.ExpiresOn.Format(time.DateOnly)
			}
			author := ""
			if d.AuthorUserID != 0 {
				author = strconv.FormatInt(d.AuthorUserID, 10)
			}
			vals := []string{d.ID.String(), string(d.Scope), nullUUID(d.ProjectID), d.VulnID, d.PURL, d.PURLBase, d.Vers,
				string(d.Action), string(d.Status), string(d.Justification), d.Comment, until, author, d.AuthorLabel,
				nullUUID(d.ExpiresID)}
			for i, v := range vals {
				cols[i] = append(cols[i], v)
			}
		}
		args := []any{tx.OrgID(), part[0].CreatedAt}
		for _, c := range cols {
			args = append(args, c)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO triage_decisions (org_id, id, scope, project_id, vuln_id, purl, purl_base, vers, action, status,
			                              justification, comment, expires_on, author_user_id, author_label, expires_id, created_at)
			SELECT $1, u.id::uuid, u.scope, NULLIF(u.project, '')::uuid, u.vuln, NULLIF(u.purl, ''), u.base, NULLIF(u.vers, ''),
			       u.action, NULLIF(u.status, ''), NULLIF(u.just, ''), u.comment, NULLIF(u.until, '')::date,
			       NULLIF(u.author, '')::bigint, u.label, NULLIF(u.expires, '')::uuid, $2
			  FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[],
			              $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[], $17::text[])
			    AS u(id, scope, project, vuln, purl, base, vers, action, status, just, comment, until, author, label, expires)`,
			args...); err != nil {
			return err
		}
	}
	return nil
}

func nullUUID(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// writeChunk borne les lignes d'une instruction en lot.
const writeChunk = 1000

// findingTarget est un constat et son statut effectif enregistré.
type findingTarget struct {
	ID        uuid.UUID
	Target    Target
	Status    Status
	Decision  uuid.UUID
	ProjectID uuid.UUID
}

const targetSelect = `SELECT f.id, f.project_id, c.purl, c.purl_base, c.type, c.version, f.vuln_id, f.triage_status,
	       f.triage_decision_id
	  FROM findings f JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id`

func queryTargets(ctx context.Context, tx *db.OrgTx, where string, args ...any) ([]findingTarget, error) {
	rows, err := tx.QueryContext(ctx, targetSelect+` WHERE `+where+` ORDER BY f.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findingTarget
	for rows.Next() {
		var ft findingTarget
		var status string
		var dec uuid.NullUUID
		if err := rows.Scan(&ft.ID, &ft.ProjectID, &ft.Target.PURL, &ft.Target.PURLBase, &ft.Target.PURLType,
			&ft.Target.Version, &ft.Target.VulnID, &status, &dec); err != nil {
			return nil, err
		}
		ft.Target.ProjectID, ft.Status, ft.Decision = ft.ProjectID, Status(status), dec.UUID
		out = append(out, ft)
	}
	return out, rows.Err()
}

// Change est le changement de statut effectif d'un constat, rendu à Options.OnChange
// dans la transaction qui le produit (point d'accroche des alertes de T15).
type Change struct {
	FindingID  uuid.UUID
	ProjectID  uuid.UUID
	VulnID     string
	PURL       string
	From, To   Status
	DecisionID uuid.UUID // décision appliquée, uuid.Nil : aucune
}

// apply recalcule le statut effectif des constats et enregistre ceux qui changent.
func (s *Service) apply(ctx context.Context, tx *db.OrgTx, targets []findingTarget) ([]Change, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	seen := map[pair]bool{}
	var pairs []pair
	for _, t := range targets {
		p := pair{t.Target.PURLBase, t.Target.VulnID}
		if !seen[p] {
			seen[p] = true
			pairs = append(pairs, p)
		}
	}
	slices.SortFunc(pairs, comparePairs)
	logs, err := decisionsFor(ctx, tx, pairs)
	if err != nil {
		return nil, err
	}
	var changes []Change
	for _, t := range targets {
		e := s.resolver.Resolve(t.Target, logs[pair{t.Target.PURLBase, t.Target.VulnID}])
		dec := uuid.Nil
		if e.Decision != nil {
			dec = e.Decision.ID
		}
		if e.Status == t.Status && dec == t.Decision {
			continue
		}
		changes = append(changes, Change{FindingID: t.ID, ProjectID: t.ProjectID, VulnID: t.Target.VulnID, PURL: t.Target.PURL,
			From: t.Status, To: e.Status, DecisionID: dec})
	}
	for start := 0; start < len(changes); start += writeChunk {
		part := changes[start:min(start+writeChunk, len(changes))]
		ids, statuses, decs := make([]string, len(part)), make([]string, len(part)), make([]string, len(part))
		for i, c := range part {
			ids[i], statuses[i], decs[i] = c.FindingID.String(), string(c.To), nullUUID(c.DecisionID)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings f SET triage_status = u.status, triage_decision_id = NULLIF(u.dec, '')::uuid
			  FROM unnest($1::uuid[], $2::text[], $3::text[]) AS u(id, status, dec) WHERE f.id = u.id`,
			ids, statuses, decs); err != nil {
			return nil, err
		}
	}
	if len(changes) > 0 && s.o.OnChange != nil {
		if err := s.o.OnChange(ctx, tx, changes); err != nil {
			return nil, err
		}
	}
	return changes, nil
}

// recompute recalcule les constats des couples.
func (s *Service) recompute(ctx context.Context, tx *db.OrgTx, pairs []pair) ([]Change, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	bases, vulns := splitPairs(pairs)
	targets, err := queryTargets(ctx, tx, `(c.purl_base, f.vuln_id) IN (SELECT * FROM unnest($1::text[], $2::text[]))`, bases, vulns)
	if err != nil {
		return nil, err
	}
	return s.apply(ctx, tx, targets)
}

// Classify calcule le statut effectif de constats qui viennent d'être créés ou rouverts,
// dans la transaction de l'analyse qui les écrit (finding.Classifier) : un constat apparu
// après une décision en hérite. Le verrou partagé l'ordonne avec les décisions.
func (s *Service) Classify(ctx context.Context, tx *db.OrgTx, findingIDs []uuid.UUID) error {
	if len(findingIDs) == 0 {
		return nil
	}
	// Le verrou d'abord : une première décision en cours de validation doit être vue.
	if err := lock(ctx, tx, false); err != nil {
		return wrap("verrou du triage", err)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM triage_decisions)`).Scan(&exists); err != nil {
		return wrap("décisions existantes", err)
	}
	if !exists {
		return nil
	}
	targets, err := queryTargets(ctx, tx, `f.id = ANY($1::uuid[])`, findingIDs)
	if err != nil {
		return wrap("constats à classer", err)
	}
	_, err = s.apply(ctx, tx, targets)
	return wrap("classement des constats", err)
}

// errNoRows dit si err signale une ligne absente.
func errNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
