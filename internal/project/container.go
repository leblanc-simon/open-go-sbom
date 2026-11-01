package project

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// Conteneurs : projets enfants d'un hôte (T13, ADR 0040). L'agent serveur signale les
// conteneurs qui tournent sur son hôte (SightContainers) ; un conteneur inconnu devient
// un projet enfant, dans l'équipe de l'hôte, avec une référence de nature « container »
// nommée par son identité ; un conteneur absent depuis plus de N jours est archivé
// (ArchiveAbsent) et revient s'il redémarre.

// Clés de validation d'un signalement de conteneurs.
const (
	KeyContainerInvalid  = "validation.container_invalid"
	KeyContainersTooMany = "validation.containers_too_many"
)

// MaxContainers borne les conteneurs d'un signalement (identités distinctes).
const MaxContainers = 500

// Bornes du contexte d'un conteneur.
const (
	maxContainerNames = 16
	maxImageRef       = 255
	maxReplicas       = 10000
)

// Moteurs de conteneurs reconnus (containerd seul : T22).
const (
	EngineDocker = "docker"
	EnginePodman = "podman"
)

// containerKeyPattern : identité d'un conteneur dans son hôte, « projet/service » pour un
// service Compose ou nom du conteneur. Les noms de projets et de services Compose et les
// noms de conteneurs commencent par une lettre ou un chiffre puis n'ont que des lettres,
// chiffres, « _ », « . » et « - » : la barre ne peut venir que de la forme Compose, et
// les deux formes ne se confondent pas.
var containerKeyPattern = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/[A-Za-z0-9][A-Za-z0-9_.-]{0,126}|[A-Za-z0-9][A-Za-z0-9_.-]{0,254})$`)

var (
	containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	composePartPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	imageIDPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidContainerKey dit si key est une identité de conteneur.
func ValidContainerKey(key string) bool { return containerKeyPattern.MatchString(key) }

// ContainerContext décrit un conteneur tel que l'agent l'a vu : moteur, noms (des
// répliques d'un même service), image et son empreinte, étiquettes Compose, démarrage.
type ContainerContext struct {
	Engine         string     `json:"engine"`
	Names          []string   `json:"names"`
	Replicas       int        `json:"replicas"`
	Image          string     `json:"image"`
	ImageID        string     `json:"image_id"`
	ComposeProject string     `json:"compose_project,omitempty"`
	ComposeService string     `json:"compose_service,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
}

// ShortImageID renvoie l'empreinte de l'image abrégée pour l'affichage (12 chiffres).
func (c ContainerContext) ShortImageID() string {
	id := strings.TrimPrefix(c.ImageID, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

// Validate vérifie un contexte venu d'un agent.
func (c ContainerContext) Validate(now time.Time) error {
	bad := func() error { return invalid("containers", KeyContainerInvalid) }
	if c.Engine != EngineDocker && c.Engine != EnginePodman {
		return bad()
	}
	if len(c.Names) == 0 || len(c.Names) > maxContainerNames || c.Replicas < 1 || c.Replicas > maxReplicas {
		return bad()
	}
	for _, n := range c.Names {
		if !containerNamePattern.MatchString(n) {
			return bad()
		}
	}
	if c.Image == "" || len(c.Image) > maxImageRef ||
		strings.ContainsFunc(c.Image, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) }) {
		return bad()
	}
	if !imageIDPattern.MatchString(c.ImageID) {
		return bad()
	}
	if (c.ComposeProject == "") != (c.ComposeService == "") ||
		c.ComposeProject != "" && (!composePartPattern.MatchString(c.ComposeProject) || !composePartPattern.MatchString(c.ComposeService)) {
		return bad()
	}
	if c.StartedAt != nil && (c.StartedAt.After(now.Add(time.Hour)) || c.StartedAt.Year() < 2000) {
		return bad()
	}
	return nil
}

// Container est l'identité et l'état d'un projet de conteneur.
type Container struct {
	// Key est son identité dans l'hôte, aussi nom de sa référence.
	Key     string
	Context ContainerContext
	// SeenAt est son dernier signalement par l'agent de l'hôte.
	SeenAt time.Time
	// ArchivedAbsent : archivé pour absence ; il revient quand l'agent le revoit.
	ArchivedAbsent bool
}

func readContainer(key string, data []byte, seen sql.NullTime, absent bool) (Container, error) {
	c := Container{Key: key, ArchivedAbsent: absent}
	if seen.Valid {
		c.SeenAt = seen.Time
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &c.Context); err != nil {
			return Container{}, fmt.Errorf("contexte du conteneur : %w", err)
		}
	}
	return c, nil
}

// ContainerSighting est un conteneur (ou les répliques d'un service) signalé par
// l'agent de l'hôte.
type ContainerSighting struct {
	Key     string
	Context ContainerContext
}

// ValidateSightings vérifie un signalement : identités valides et distinctes, contextes
// bornés, MaxContainers au plus.
func ValidateSightings(s []ContainerSighting, now time.Time) error {
	if len(s) > MaxContainers {
		return invalid("containers", KeyContainersTooMany)
	}
	seen := make(map[string]bool, len(s))
	for _, c := range s {
		if !ValidContainerKey(c.Key) || seen[c.Key] {
			return invalid("containers", KeyContainerInvalid)
		}
		seen[c.Key] = true
		if err := c.Context.Validate(now); err != nil {
			return err
		}
	}
	return nil
}

// ChildState est la réponse du serveur pour un conteneur signalé.
type ChildState struct {
	Key       string
	ProjectID uuid.UUID
	Slug      string
	RefID     uuid.UUID
	// Ignored : un utilisateur a archivé ce projet ; l'agent ne l'inventorie pas.
	Ignored bool
	// Created : projet créé par ce signalement ; Reactivated : archivé pour absence, il
	// revient.
	Created     bool
	Reactivated bool
}

// ErrNoHost : l'agent n'a pas de projet d'hôte actif (agent dépôt, hôte archivé).
var ErrNoHost = errors.New("project: aucun hôte actif confié à l'agent")

// SightContainers enregistre, dans la transaction InOrg de l'appelant, les conteneurs
// qui tournent sur l'hôte confié à agentID : un conteneur inconnu devient un projet
// enfant de cet hôte (et de lui seul : l'agent ne désigne jamais l'hôte), dans son
// équipe ; un conteneur connu met à jour son contexte et sa date de signalement, et
// revient s'il était archivé pour absence. Le projet de l'hôte est verrouillé : deux
// signalements du même agent se succèdent. actor journalise créations et retours.
func SightContainers(ctx context.Context, tx *db.OrgTx, actor audit.Actor, agentID uuid.UUID, sightings []ContainerSighting,
	now time.Time) ([]ChildState, error) {
	var host ParentRef
	var team uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id, slug, name, team_id FROM projects
		 WHERE agent_id = $1 AND kind = 'host' AND archived_at IS NULL FOR UPDATE`, agentID).
		Scan(&host.ID, &host.Slug, &host.Name, &team)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoHost
	}
	if err != nil {
		return nil, wrap("hôte d'un agent", err)
	}
	sorted := slices.Clone(sightings)
	slices.SortFunc(sorted, func(a, b ContainerSighting) int { return strings.Compare(a.Key, b.Key) })
	out := make([]ChildState, 0, len(sorted))
	for _, s := range sorted {
		st, err := sightContainer(ctx, tx, actor, host, team, s, now)
		if err != nil {
			return nil, wrap("conteneur signalé", err)
		}
		out = append(out, st)
	}
	return out, nil
}

func sightContainer(ctx context.Context, tx *db.OrgTx, actor audit.Actor, host ParentRef, team uuid.UUID, s ContainerSighting,
	now time.Time) (ChildState, error) {
	st := ChildState{Key: s.Key}
	data, err := json.Marshal(s.Context)
	if err != nil {
		return st, err
	}
	var archived sql.NullTime
	var absent bool
	err = tx.QueryRowContext(ctx, `SELECT id, slug, archived_at, archived_absent FROM projects
		 WHERE parent_id = $1 AND kind = 'container' AND container_key = $2 FOR UPDATE`, host.ID, s.Key).
		Scan(&st.ProjectID, &st.Slug, &archived, &absent)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := insertContainer(ctx, tx, host, team, s.Key, data, now, &st); err != nil {
			return st, err
		}
		st.Created = true
		return st, audit.RecordOrg(ctx, tx, actor, audit.Event{Action: audit.ProjectCreated, TargetType: "project",
			TargetID: st.ProjectID.String(), TargetLabel: st.Slug,
			Details: map[string]string{"kind": string(KindContainer), "host": host.Slug}})
	case err != nil:
		return st, err
	}
	st.Reactivated = archived.Valid && absent
	st.Ignored = archived.Valid && !absent
	if _, err := tx.ExecContext(ctx, `UPDATE projects SET container = $2, seen_at = $3,
		archived_at = CASE WHEN archived_absent THEN NULL ELSE archived_at END, archived_absent = false
		 WHERE id = $1`, st.ProjectID, data, now); err != nil {
		return st, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT id FROM tracked_refs WHERE project_id = $1 AND kind = 'container'`, st.ProjectID).
		Scan(&st.RefID); err != nil {
		return st, err
	}
	if st.Reactivated {
		return st, audit.RecordOrg(ctx, tx, actor, audit.Event{Action: audit.ProjectUnarchived, TargetType: "project",
			TargetID: st.ProjectID.String(), TargetLabel: st.Slug, Details: map[string]string{"reason": "reappeared"}})
	}
	return st, nil
}

// insertContainer crée le projet enfant et sa référence : nom « hôte/identité », slug
// dérivé et rendu unique, équipe de l'hôte.
func insertContainer(ctx context.Context, tx *db.OrgTx, host ParentRef, team uuid.UUID, key string, data []byte, now time.Time,
	st *ChildState) error {
	name := clipRunes(host.Name+"/"+key, maxName)
	slug, err := freeSlug(ctx, tx, Slugify(host.Slug+"-"+key))
	if err != nil {
		return err
	}
	if st.ProjectID, err = uuid.NewV7(); err != nil {
		return err
	}
	st.Slug = slug
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO projects (org_id, id, kind, slug, name, team_id, parent_id, parent_kind, container_key, container, seen_at)
		VALUES ($1, $2, 'container', $3, $4, $5, $6, 'host', $7, $8, $9)`,
		tx.OrgID(), st.ProjectID, slug, name, team, host.ID, key, data, now); err != nil {
		return err
	}
	st.RefID = uuid.Must(uuid.NewV7())
	_, err = tx.ExecContext(ctx, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
		VALUES ($1, $2, $3, 'container', 'container', $4)`, tx.OrgID(), st.RefID, st.ProjectID, key)
	return err
}

// clipRunes coupe s à n caractères au plus.
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ArchiveAbsent archive, dans la transaction InOrg de l'appelant, les conteneurs actifs
// qui n'ont plus été signalés depuis before, et en renvoie le nombre. Chacun est
// journalisé (acteur système, motif « absent ») ; il reviendra s'il redémarre.
func ArchiveAbsent(ctx context.Context, tx *db.OrgTx, before, now time.Time) (int, error) {
	rows, err := tx.QueryContext(ctx, `UPDATE projects SET archived_at = $2, archived_absent = true, updated_at = $2
		 WHERE kind = 'container' AND archived_at IS NULL AND seen_at < $1 RETURNING id, slug`, before, now)
	if err != nil {
		return 0, wrap("archivage des conteneurs absents", err)
	}
	type row struct {
		id   uuid.UUID
		slug string
	}
	var archived []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.slug); err != nil {
			rows.Close()
			return 0, wrap("archivage des conteneurs absents", err)
		}
		archived = append(archived, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, wrap("archivage des conteneurs absents", err)
	}
	for _, r := range archived {
		if err := audit.RecordOrg(ctx, tx, audit.System, audit.Event{Action: audit.ProjectArchived, TargetType: "project",
			TargetID: r.id.String(), TargetLabel: r.slug, Details: map[string]string{"reason": "absent"}}); err != nil {
			return 0, wrap("journal de l'archivage", err)
		}
	}
	return len(archived), nil
}

// Children renvoie les conteneurs visibles d'un hôte, actifs d'abord, par nom.
func (s *Service) Children(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, hostID uuid.UUID) ([]Project, error) {
	var out []Project
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+columns+from+`
			 WHERE p.parent_id = $1 AND p.kind = 'container' AND lotor_team_visible(p.team_id)
			 ORDER BY p.archived_at IS NOT NULL, lower(p.name), p.id LIMIT $2`, hostID, MaxContainers)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("conteneurs d'un hôte", err)
}
