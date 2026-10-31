package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// Priorités usuelles : la plus haute passe d'abord. Toute valeur de [MinPriority,
// MaxPriority] est admise.
const (
	PriorityLow    = -100 // travail de fond (réanalyse de toutes les références)
	PriorityNormal = 0
	PriorityHigh   = 100 // conséquence directe d'une action (ingestion fraîche)

	MinPriority = -1000
	MaxPriority = 1000
)

// DefaultMaxAttempts est le nombre de tentatives d'un job qui n'en précise pas.
const DefaultMaxAttempts = 10

// MaxAttemptsLimit borne Job.MaxAttempts.
const MaxAttemptsLimit = 100

// MaxPayloadSize borne la charge utile : elle ne porte que des références que le handler
// relit en base, jamais un document.
const MaxPayloadSize = 16 << 10

const maxUniqueKeyLen = 200

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

var (
	// ErrInvalidJob : job mal formé (type, priorité, charge utile…).
	ErrInvalidJob = errors.New("jobs: job invalide")
	// ErrUniqueKeyConflict : la clé d'unicité est déjà en attente pour une autre
	// organisation. Les deux jobs ne sont jamais fusionnés.
	ErrUniqueKeyConflict = errors.New("jobs: clé d'unicité déjà en attente pour une autre organisation")
	// ErrOrgMismatch : le job vise une autre organisation que la transaction InOrg qui le
	// met en file.
	ErrOrgMismatch = errors.New("jobs: organisation du job différente de celle de la transaction")
	// ErrNotFound : aucun job ne correspond (identifiant inconnu ou statut inattendu).
	ErrNotFound = errors.New("jobs: job introuvable")
)

// Job est un traitement à mettre en file.
type Job struct {
	// Kind désigne le handler : « ingest.decode », « analysis.ref »…
	Kind string
	// OrgID est l'organisation concernée ; zéro pour un job d'instance. Mis en file dans
	// une transaction InOrg, il vaut par défaut l'organisation de la transaction.
	OrgID tenant.OrgID
	// Payload est sérialisé en JSON (nil : objet vide). Il ne contient que des références
	// que le handler relit en base : une seconde mise en file sur la même clé d'unicité
	// garde la charge du job existant.
	Payload any
	// Priority : la plus haute passe d'abord (PriorityLow, PriorityNormal, PriorityHigh).
	Priority int
	// UniqueKey, facultative, dédoublonne les jobs en attente du même type : une seconde
	// mise en file garde la plus haute priorité et l'échéance la plus proche.
	UniqueKey string
	// RunAt est l'échéance ; zéro : dès que possible.
	RunAt time.Time
	// MaxAttempts borne les tentatives avant le statut dead (zéro : DefaultMaxAttempts).
	MaxAttempts int
}

// orgScoped est implémenté par *db.OrgTx.
type orgScoped interface {
	OrgID() tenant.OrgID
}

// Enqueue met j en file dans la transaction de l'appelant : le job n'existe que si la
// transaction est validée. Il renvoie l'identifiant du job, ou celui du job en attente
// de même clé d'unicité dont la priorité et l'échéance ont été relevées.
func Enqueue(ctx context.Context, q db.Querier, j Job) (uuid.UUID, error) {
	if s, ok := q.(orgScoped); ok {
		switch {
		case j.OrgID.IsZero():
			j.OrgID = s.OrgID()
		case j.OrgID != s.OrgID():
			return uuid.Nil, ErrOrgMismatch
		}
	}
	payload, err := j.validate()
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("jobs: identifiant : %w", err)
	}
	now := time.Now()
	runAt := j.RunAt
	if runAt.IsZero() {
		runAt = now
	}
	maxAttempts := j.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = DefaultMaxAttempts
	}
	// La clause WHERE du DO UPDATE refuse de fusionner deux organisations : aucune ligne
	// n'est alors renvoyée.
	var got uuid.UUID
	err = q.QueryRowContext(ctx, `
		INSERT INTO jobs (id, kind, org_id, payload, priority, max_attempts, run_at, unique_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
		ON CONFLICT (kind, unique_key) WHERE status = 'pending' AND unique_key IS NOT NULL
		DO UPDATE SET
			priority   = GREATEST(jobs.priority, EXCLUDED.priority),
			run_at     = LEAST(jobs.run_at, EXCLUDED.run_at),
			updated_at = EXCLUDED.updated_at
		WHERE jobs.org_id IS NOT DISTINCT FROM EXCLUDED.org_id
		RETURNING id`,
		id, j.Kind, nullOrg(j.OrgID), payload, j.Priority, maxAttempts, runAt, nullString(j.UniqueKey), now,
	).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrUniqueKeyConflict
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("jobs: mise en file de %s : %w", j.Kind, err)
	}
	return got, nil
}

func (j Job) validate() ([]byte, error) {
	if err := validKind(j.Kind); err != nil {
		return nil, err
	}
	if j.Priority < MinPriority || j.Priority > MaxPriority {
		return nil, fmt.Errorf("%w : priorité %d hors de [%d, %d]", ErrInvalidJob, j.Priority, MinPriority, MaxPriority)
	}
	if j.MaxAttempts < 0 || j.MaxAttempts > MaxAttemptsLimit {
		return nil, fmt.Errorf("%w : max_attempts %d hors de [1, %d]", ErrInvalidJob, j.MaxAttempts, MaxAttemptsLimit)
	}
	if len(j.UniqueKey) > maxUniqueKeyLen {
		return nil, fmt.Errorf("%w : clé d'unicité de plus de %d octets", ErrInvalidJob, maxUniqueKeyLen)
	}
	payload := []byte("{}")
	if j.Payload != nil {
		var err error
		if payload, err = json.Marshal(j.Payload); err != nil {
			return nil, fmt.Errorf("%w : charge utile : %v", ErrInvalidJob, err)
		}
	}
	if len(payload) > MaxPayloadSize {
		return nil, fmt.Errorf("%w : charge utile de %d octets (au plus %d : des références, pas des documents)",
			ErrInvalidJob, len(payload), MaxPayloadSize)
	}
	return payload, nil
}

func validKind(kind string) error {
	if len(kind) > 64 || !kindPattern.MatchString(kind) {
		return fmt.Errorf("%w : type %q (attendu « domaine.action » en minuscules)", ErrInvalidJob, kind)
	}
	return nil
}

func nullOrg(o tenant.OrgID) any {
	if o.IsZero() {
		return nil
	}
	return o
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
