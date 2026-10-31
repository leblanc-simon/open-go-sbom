package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/inventory"
	"leblanc.io/open-go-sbom/internal/jobs"
	"leblanc.io/open-go-sbom/internal/tenant"
	"leblanc.io/open-go-sbom/internal/vuln"
)

// Engine est la base de vulnérabilités de l'instance (vuln.Manager) : Ensure la
// synchronise sur la cible, Match confronte un SBOM à la base chargée.
type Engine interface {
	Ensure(ctx context.Context) (vuln.Version, error)
	Match(ctx context.Context, blob []byte) (vuln.Result, error)
}

// BlobSource lit un SBOM d'origine (ingest.Service).
type BlobSource interface {
	Blob(ctx context.Context, org tenant.OrgID, blobID uuid.UUID) ([]byte, error)
}

// Outcome est l'issue d'une analyse.
type Outcome string

// Issues d'une analyse.
const (
	OutcomeAnalyzed    Outcome = "analyzed"
	OutcomeUpToDate    Outcome = "up_to_date"   // même ensemble, même base : rien à faire
	OutcomeNoInventory Outcome = "no_inventory" // référence sans instantané
	OutcomeNoDatabase  Outcome = "no_database"  // aucune base encore : la première cible réanalysera tout
	OutcomeSuperseded  Outcome = "superseded"   // l'ensemble a changé pendant l'analyse ; un autre job suit
	OutcomeUnknownRef  Outcome = "unknown_ref"
)

// maxAttempts borne les reprises d'une analyse dont la base cible change pendant la
// correspondance.
const maxAttempts = 3

// Options règle un Analyzer.
type Options struct {
	Pool   *db.Pool
	Engine Engine
	Blobs  BlobSource
	Logger *slog.Logger
	Now    func() time.Time
}

// Analyzer exécute les analyses de vulnérabilités et tient les constats.
type Analyzer struct {
	o Options
}

// NewAnalyzer renvoie un Analyzer.
func NewAnalyzer(o Options) *Analyzer {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Analyzer{o: o}
}

// Handler est le handler du job analysis.ref (inventory.AnalysisKind).
func (a *Analyzer) Handler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p inventory.AnalysisPayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		if e.OrgID.IsZero() || p.RefID == uuid.Nil {
			return jobs.Permanent(errors.New("finding: job d'analyse sans organisation ni référence"))
		}
		out, err := a.Analyze(ctx, e.OrgID, p.RefID)
		if err == nil {
			a.o.Logger.Debug("analyse", "org", e.OrgID, "ref", p.RefID, "outcome", out)
		}
		return err
	})
}

// refState est ce qu'une analyse lit d'une référence avant la correspondance.
type refState struct {
	ProjectID  uuid.UUID
	SetID      uuid.UUID
	SnapshotID uuid.UUID
	BlobID     uuid.UUID
	HasCurrent bool
	// Analysed : ensemble et base de la dernière analyse.
	AnalysedSet     uuid.UUID
	AnalysedArchive uuid.UUID
}

func readRef(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) (refState, error) {
	var s refState
	var set, snap, blob, aset, aarch uuid.NullUUID
	err := tx.QueryRowContext(ctx, `
		SELECT r.project_id, rc.set_id, rc.snapshot_id, sn.blob_id, ra.set_id, ra.vulndb_archive
		  FROM tracked_refs r
		  LEFT JOIN ref_current rc ON rc.org_id = r.org_id AND rc.ref_id = r.id
		  LEFT JOIN snapshots sn ON sn.org_id = rc.org_id AND sn.id = rc.snapshot_id
		  LEFT JOIN ref_analyses ra ON ra.org_id = r.org_id AND ra.ref_id = r.id
		 WHERE r.id = $1`, refID).Scan(&s.ProjectID, &set, &snap, &blob, &aset, &aarch)
	if err != nil {
		return refState{}, err
	}
	s.HasCurrent = set.Valid
	s.SetID, s.SnapshotID, s.BlobID, s.AnalysedSet, s.AnalysedArchive = set.UUID, snap.UUID, blob.UUID, aset.UUID, aarch.UUID
	return s, nil
}

// Analyze analyse l'ensemble courant de la référence avec la base cible. La
// correspondance se fait hors transaction ; l'écriture des constats, elle, se fait sous
// verrou de ligne de la référence, après avoir vérifié que l'ensemble courant et la base
// cible sont toujours ceux de la correspondance : deux analyses de la même référence ne
// mêlent jamais leurs écritures, et un worker en retard n'écrase jamais un résultat plus
// récent. Idempotent : un même couple (ensemble, base) n'est analysé qu'une fois.
func (a *Analyzer) Analyze(ctx context.Context, org tenant.OrgID, refID uuid.UUID) (Outcome, error) {
	for range maxAttempts {
		out, retry, err := a.attempt(ctx, org, refID)
		if err != nil || !retry {
			return out, err
		}
	}
	return "", fmt.Errorf("finding: la base cible a changé %d fois pendant l'analyse de %s", maxAttempts, refID)
}

func (a *Analyzer) attempt(ctx context.Context, org tenant.OrgID, refID uuid.UUID) (Outcome, bool, error) {
	version, err := a.o.Engine.Ensure(ctx)
	if errors.Is(err, vuln.ErrNoDatabase) {
		return OutcomeNoDatabase, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("finding: base de vulnérabilités : %w", err)
	}
	var st refState
	err = a.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		st, err = readRef(ctx, tx, refID)
		return err
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return OutcomeUnknownRef, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("finding: état de la référence : %w", err)
	}
	if !st.HasCurrent {
		return OutcomeNoInventory, false, nil
	}
	if st.AnalysedSet == st.SetID && st.AnalysedArchive == version.ArchiveID {
		return OutcomeUpToDate, false, nil
	}
	blob, err := a.o.Blobs.Blob(ctx, org, st.BlobID)
	if err != nil {
		return "", false, fmt.Errorf("finding: SBOM d'origine : %w", err)
	}
	res, err := a.o.Engine.Match(ctx, blob)
	if errors.Is(err, vuln.ErrNoDatabase) {
		return OutcomeNoDatabase, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("finding: correspondance : %w", err)
	}
	now := a.o.Now()
	// Catalogue global d'abord, dans sa propre transaction courte : les constats y font
	// référence, et ses lignes, partagées par toutes les analyses, ne restent pas
	// verrouillées pendant l'écriture des constats.
	if err := a.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		return vuln.UpsertCatalog(ctx, tx, res.Vulnerabilities, res.Version.Built, now)
	}); err != nil {
		return "", false, fmt.Errorf("finding: catalogue : %w", err)
	}
	var out Outcome
	retry := false
	err = a.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM tracked_refs WHERE id = $1 FOR UPDATE`, refID); err != nil {
			return err
		}
		var setID, snapshotID uuid.UUID
		if err := tx.QueryRowContext(ctx, `SELECT set_id, snapshot_id FROM ref_current WHERE ref_id = $1`, refID).
			Scan(&setID, &snapshotID); err != nil {
			return err
		}
		if setID != st.SetID {
			out = OutcomeSuperseded
			return nil
		}
		target, err := vuln.TargetVersion(ctx, tx)
		if err != nil {
			return err
		}
		if target.ArchiveID != res.Version.ArchiveID {
			retry = true
			return nil
		}
		st.SnapshotID = snapshotID
		out = OutcomeAnalyzed
		return a.write(ctx, tx, refID, st, res, now)
	})
	if err != nil {
		return "", false, fmt.Errorf("finding: écriture des constats : %w", err)
	}
	return out, retry, nil
}

// write applique la correspondance aux constats de la référence, dans la transaction
// qui la tient verrouillée.
func (a *Analyzer) write(ctx context.Context, tx *db.OrgTx, refID uuid.UUID, st refState, res vuln.Result, now time.Time) error {
	purls := make([]string, 0, len(res.Matches))
	for _, m := range res.Matches {
		purls = append(purls, m.PURL)
	}
	components := map[string]uuid.UUID{}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.purl, c.id FROM component_set_items i
		  JOIN components c ON c.org_id = i.org_id AND c.id = i.component_id
		 WHERE i.set_id = $1 AND c.purl = ANY($2::text[])`, st.SetID, purls)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p string
		var id uuid.UUID
		if err := rows.Scan(&p, &id); err != nil {
			rows.Close()
			return err
		}
		components[p] = id
	}
	if err := closeRows(rows); err != nil {
		return err
	}
	seen, unmatched := merge(res.Matches, components, res.Vulnerabilities)
	existing, err := currentFindings(ctx, tx, refID)
	if err != nil {
		return err
	}
	inSet, err := componentsInSet(ctx, tx, st.SetID, existing)
	if err != nil {
		return err
	}
	p := planFor(existing, seen, inSet)
	w := writer{tx: tx, refID: refID, st: st, v: res.Version, now: now}
	if err := w.create(ctx, p.Create); err != nil {
		return fmt.Errorf("nouveaux constats : %w", err)
	}
	if err := w.update(ctx, p.Update); err != nil {
		return fmt.Errorf("constats revus : %w", err)
	}
	if err := w.resolve(ctx, p.Resolve); err != nil {
		return fmt.Errorf("constats résolus : %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ref_analyses (org_id, ref_id, project_id, set_id, snapshot_id, vulndb_archive, vulndb_built, analyzed_at,
		                          match_count, unmatched_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id, ref_id) DO UPDATE SET set_id = EXCLUDED.set_id, snapshot_id = EXCLUDED.snapshot_id,
		    vulndb_archive = EXCLUDED.vulndb_archive, vulndb_built = EXCLUDED.vulndb_built,
		    analyzed_at = EXCLUDED.analyzed_at, match_count = EXCLUDED.match_count, unmatched_count = EXCLUDED.unmatched_count`,
		tx.OrgID(), refID, st.ProjectID, st.SetID, st.SnapshotID, res.Version.ArchiveID, res.Version.Built, now,
		len(seen), unmatched)
	return err
}

func closeRows(rows *sql.Rows) error {
	if err := rows.Close(); err != nil {
		return err
	}
	return rows.Err()
}

func currentFindings(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) ([]current, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, component_id, vuln_id, status FROM findings WHERE ref_id = $1`, refID)
	if err != nil {
		return nil, err
	}
	var out []current
	for rows.Next() {
		var c current
		var status string
		if err := rows.Scan(&c.ID, &c.key.Component, &c.key.Vuln, &status); err != nil {
			rows.Close()
			return nil, err
		}
		c.Status = Status(status)
		out = append(out, c)
	}
	return out, closeRows(rows)
}

// componentsInSet dit lesquels des composants des constats ouverts sont encore dans
// l'ensemble analysé.
func componentsInSet(ctx context.Context, tx *db.OrgTx, setID uuid.UUID, cs []current) (map[uuid.UUID]bool, error) {
	ids := make([]uuid.UUID, 0, len(cs))
	for _, c := range cs {
		if c.Status == StatusOpen {
			ids = append(ids, c.key.Component)
		}
	}
	out := map[uuid.UUID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT component_id FROM component_set_items WHERE set_id = $1 AND component_id = ANY($2::uuid[])`,
		setID, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		out[id] = true
	}
	return out, closeRows(rows)
}

// writeChunk borne les lignes d'une instruction en lot.
const writeChunk = 1000

type writer struct {
	tx    *db.OrgTx
	refID uuid.UUID
	st    refState
	v     vuln.Version
	now   time.Time
}

// columns sérialise les attributs observés pour unnest.
type columns struct {
	ids, comps, vulns, sev, cvss, epss, pct, kev, risk, fixed, state, mtype []string
}

func (c *columns) add(id uuid.UUID, o observed) {
	c.ids = append(c.ids, id.String())
	c.comps = append(c.comps, o.Component.String())
	c.vulns = append(c.vulns, o.Vuln)
	c.sev = append(c.sev, string(o.Severity))
	cv, e, p := "", "", ""
	if o.CVSS > 0 {
		cv = strconv.FormatFloat(o.CVSS, 'f', 1, 64)
	}
	if o.EPSS != nil {
		e, p = strconv.FormatFloat(o.EPSS.Score, 'f', 5, 64), strconv.FormatFloat(o.EPSS.Percentile, 'f', 5, 64)
	}
	c.cvss, c.epss, c.pct = append(c.cvss, cv), append(c.epss, e), append(c.pct, p)
	c.kev = append(c.kev, strconv.FormatBool(o.KEV))
	c.risk = append(c.risk, strconv.FormatFloat(min(max(o.Risk, 0), 100), 'f', 2, 64))
	c.fixed = append(c.fixed, joinList(o.FixedVersions))
	c.state = append(c.state, string(o.FixState))
	c.mtype = append(c.mtype, string(o.MatchType))
}

func (c *columns) args() []any {
	return []any{c.ids, c.comps, c.vulns, c.sev, c.cvss, c.epss, c.pct, c.kev, c.risk, c.fixed, c.state, c.mtype}
}

func joinList(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += "\x1f"
		}
		out += v
	}
	return out
}

const unnestColumns = `unnest($1::uuid[], $2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
	$9::text[], $10::text[], $11::text[], $12::text[])
	AS u(id, component_id, vuln_id, severity, cvss, epss, pct, kev, risk, fixed, fix_state, match_type)`

func (w writer) event(ctx context.Context, ids []string, kind string, reasons []string) error {
	_, err := w.tx.ExecContext(ctx, `
		INSERT INTO finding_events (org_id, finding_id, at, kind, resolution, snapshot_id, vulndb_archive)
		SELECT $1, u.id, $2, $3, NULLIF(u.reason, ''), $4, $5 FROM unnest($6::uuid[], $7::text[]) AS u(id, reason)`,
		w.tx.OrgID(), w.now, kind, w.st.SnapshotID, w.v.ArchiveID, ids, reasons)
	return err
}

func (w writer) create(ctx context.Context, os []observed) error {
	for start := 0; start < len(os); start += writeChunk {
		var c columns
		for _, o := range os[start:min(start+writeChunk, len(os))] {
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			c.add(id, o)
		}
		args := append(c.args(), w.tx.OrgID(), w.st.ProjectID, w.refID, w.now, w.st.SnapshotID, w.v.ArchiveID, w.v.Built)
		if _, err := w.tx.ExecContext(ctx, `
			INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status, severity, cvss_score, epss,
			                      epss_percentile, kev, risk, fixed_versions, fix_state, match_type, first_seen_at, last_seen_at,
			                      snapshot_id, vulndb_archive, vulndb_built, updated_at)
			SELECT $13, u.id, $14, $15, u.component_id, u.vuln_id, 'open', u.severity, NULLIF(u.cvss, '')::numeric,
			       NULLIF(u.epss, '')::numeric, NULLIF(u.pct, '')::numeric, u.kev::boolean, u.risk::numeric,
			       string_to_array(u.fixed, E'\x1f'), u.fix_state, u.match_type, $16, $16, $17, $18, $19, $16
			  FROM `+unnestColumns, args...); err != nil {
			return err
		}
		if err := w.event(ctx, c.ids, "opened", make([]string, len(c.ids))); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) update(ctx context.Context, cs []change) error {
	for start := 0; start < len(cs); start += writeChunk {
		var c columns
		var reopened []string
		for _, ch := range cs[start:min(start+writeChunk, len(cs))] {
			c.add(ch.ID, ch.Obs)
			if ch.Reopen {
				reopened = append(reopened, ch.ID.String())
			}
		}
		args := append(c.args(), w.now, w.st.SnapshotID, w.v.ArchiveID, w.v.Built)
		if _, err := w.tx.ExecContext(ctx, `
			UPDATE findings f SET status = 'open', resolution = NULL, resolved_at = NULL, severity = u.severity,
			       cvss_score = NULLIF(u.cvss, '')::numeric, epss = NULLIF(u.epss, '')::numeric,
			       epss_percentile = NULLIF(u.pct, '')::numeric, kev = u.kev::boolean, risk = u.risk::numeric,
			       fixed_versions = string_to_array(u.fixed, E'\x1f'), fix_state = u.fix_state, match_type = u.match_type,
			       last_seen_at = $13, snapshot_id = $14, vulndb_archive = $15, vulndb_built = $16, updated_at = $13
			  FROM `+unnestColumns+` WHERE f.id = u.id`, args...); err != nil {
			return err
		}
		if len(reopened) > 0 {
			if err := w.event(ctx, reopened, "reopened", make([]string, len(reopened))); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) resolve(ctx context.Context, rs []resolution) error {
	for start := 0; start < len(rs); start += writeChunk {
		part := rs[start:min(start+writeChunk, len(rs))]
		ids, reasons := make([]string, len(part)), make([]string, len(part))
		for i, r := range part {
			ids[i], reasons[i] = r.ID.String(), string(r.Reason)
		}
		if _, err := w.tx.ExecContext(ctx, `
			UPDATE findings f SET status = 'resolved', resolution = u.reason, resolved_at = $3, updated_at = $3,
			       vulndb_archive = $4, vulndb_built = $5
			  FROM unnest($1::uuid[], $2::text[]) AS u(id, reason) WHERE f.id = u.id`,
			ids, reasons, w.now, w.v.ArchiveID, w.v.Built); err != nil {
			return err
		}
		if err := w.event(ctx, ids, "resolved", reasons); err != nil {
			return err
		}
	}
	return nil
}
