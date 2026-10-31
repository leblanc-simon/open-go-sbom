package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/token"
)

// Jetons d'accès personnels (ogsbom_pat_…, ADR 0025) : une donnée du compte. Un jeton
// ouvre en lecture seule l'API utilisateur des organisations dont son propriétaire est
// membre au moment de la requête ; il ne donne jamais plus que le compte.

// Bornes des jetons personnels.
const (
	// MaxPersonalTokens borne les jetons actifs (ni révoqués ni expirés) d'un compte.
	MaxPersonalTokens = 20
	// DefaultPersonalTokenDays est la durée de vie proposée à la création.
	DefaultPersonalTokenDays = 90
	maxTokenName             = 100
)

// PersonalTokenDays liste les durées de vie possibles, en jours : un jeton personnel
// expire toujours.
func PersonalTokenDays() []int { return []int{7, 30, 90, 180, 365} }

// Clés propres aux jetons personnels.
const (
	KeyTokenNameInvalid   = "validation.name_invalid"
	KeyTokenExpiryInvalid = "validation.token_expiry_invalid"
	KeyTokenLimit         = "validation.token_limit"

	KeyTokenInvalid  = "error.token.invalid"
	KeyTokenRevoked  = "error.token.revoked"
	KeyTokenExpired  = "error.token.expired"
	KeyAccountClosed = "error.token.account_inactive"
	// KeyAccountPending : le compte doit changer son mot de passe temporaire ou enrôler un
	// second facteur ; ses jetons attendent.
	KeyAccountPending = "error.token.account_pending"
)

// TokenError est le refus d'un jeton personnel. Tant que le secret n'est pas vérifié, la
// clé est toujours KeyTokenInvalid : le refus ne révèle rien d'un jeton qu'on ne détient
// pas.
type TokenError struct{ Key string }

func (e *TokenError) Error() string { return "account: jeton personnel refusé : " + e.Key }

var errTokenInvalid = &TokenError{Key: KeyTokenInvalid}

// PersonalToken est un jeton personnel tel que le profil le présente (jamais son secret).
type PersonalToken struct {
	ID         uuid.UUID
	PublicID   string
	Name       string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Prefix est le début reconnaissable du jeton (« ogsbom_pat_k7q2xa »).
func (t PersonalToken) Prefix() string { return token.DisplayPrefix(token.Personal, t.PublicID) }

// Active indique si le jeton est utilisable à l'instant now.
func (t PersonalToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// TokenPrincipal est le compte authentifié par un jeton personnel.
type TokenPrincipal struct {
	UserID   int64
	Email    string
	TokenID  uuid.UUID
	PublicID string
}

// RateKey est la clé de limitation de débit : un compteur par jeton.
func (p TokenPrincipal) RateKey() string { return string(token.Personal) + ":" + p.PublicID }

// tokenTouchEvery espace les écritures de la date de dernier usage.
const tokenTouchEvery = time.Minute

func now() time.Time { return time.Now().UTC().Round(time.Microsecond) }

func tokenEvent(action audit.Action, t PersonalToken) audit.Event {
	return audit.Event{Action: action, TargetType: "personal_token", TargetID: t.ID.String(), TargetLabel: t.Name,
		Details: map[string]string{"prefix": t.Prefix(), "expires_at": t.ExpiresAt.Format(time.RFC3339)}}
}

// CreatePersonalToken tire un jeton personnel pour userID, valable days jours (une des
// PersonalTokenDays). Le secret n'est renvoyé qu'ici.
func (s *Service) CreatePersonalToken(ctx context.Context, actor audit.Actor, userID int64, name string, days int) (PersonalToken, token.Issued, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxTokenName || !utf8.ValidString(name) || strings.ContainsFunc(name, isControl) {
		return PersonalToken{}, token.Issued{}, &ValidationError{Field: "name", Key: KeyTokenNameInvalid}
	}
	if !slices.Contains(PersonalTokenDays(), days) {
		return PersonalToken{}, token.Issued{}, &ValidationError{Field: "expires_in", Key: KeyTokenExpiryInvalid}
	}
	issued, err := token.New(token.Personal)
	if err != nil {
		return PersonalToken{}, token.Issued{}, err
	}
	at := now()
	t := PersonalToken{ID: uuid.Must(uuid.NewV7()), PublicID: issued.PublicID, Name: name, CreatedAt: at,
		ExpiresAt: at.AddDate(0, 0, days)}
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		u, err := getUser(ctx, tx, userID, true)
		if err != nil {
			return err
		}
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM personal_access_tokens
			WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2`, u.ID, at).Scan(&active); err != nil {
			return err
		}
		if active >= MaxPersonalTokens {
			return &ValidationError{Field: "name", Key: KeyTokenLimit}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO personal_access_tokens (id, user_id, public_id, secret_hash, name, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, t.ID, u.ID, t.PublicID, issued.Hash[:], t.Name, t.ExpiresAt, t.CreatedAt); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, tokenEvent(audit.PersonalTokenCreated, t))
	})
	if err != nil {
		if _, ok := IsValidation(err); ok {
			return PersonalToken{}, token.Issued{}, err
		}
		return PersonalToken{}, token.Issued{}, fmt.Errorf("account: création d'un jeton personnel : %w", err)
	}
	return t, issued, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

const personalTokenColumns = `id, public_id, name, expires_at, created_at, last_used_at, revoked_at`

func scanPersonalToken(row interface{ Scan(...any) error }) (PersonalToken, error) {
	var t PersonalToken
	var used, revoked sql.NullTime
	if err := row.Scan(&t.ID, &t.PublicID, &t.Name, &t.ExpiresAt, &t.CreatedAt, &used, &revoked); err != nil {
		return PersonalToken{}, err
	}
	t.ExpiresAt, t.CreatedAt = t.ExpiresAt.UTC(), t.CreatedAt.UTC()
	if used.Valid {
		u := used.Time.UTC()
		t.LastUsedAt = &u
	}
	if revoked.Valid {
		r := revoked.Time.UTC()
		t.RevokedAt = &r
	}
	return t, nil
}

// PersonalTokens renvoie les jetons de userID, du plus récent au plus ancien (révoqués et
// expirés compris, 100 au plus).
func (s *Service) PersonalTokens(ctx context.Context, userID int64) ([]PersonalToken, error) {
	var out []PersonalToken
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+personalTokenColumns+` FROM personal_access_tokens
			WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 100`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanPersonalToken(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	}, db.ReadOnly())
	if err != nil {
		return nil, fmt.Errorf("account: jetons personnels : %w", err)
	}
	return out, nil
}

// ErrTokenNotFound : aucun jeton de ce compte ne porte cet identifiant.
var ErrTokenNotFound = errors.New("account: jeton personnel inconnu")

// revokePersonalTokens révoque d'office tous les jetons actifs de userID, dans la
// transaction d'une réinitialisation ou d'un changement de mot de passe, avec une entrée
// d'audit par jeton (reason : la cause).
func revokePersonalTokens(ctx context.Context, tx *db.Tx, actor audit.Actor, userID int64, reason string) error {
	at := now()
	rows, err := tx.QueryContext(ctx, `UPDATE personal_access_tokens SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
		RETURNING `+personalTokenColumns, userID, at)
	if err != nil {
		return err
	}
	var revoked []PersonalToken
	for rows.Next() {
		t, err := scanPersonalToken(rows)
		if err != nil {
			rows.Close()
			return err
		}
		revoked = append(revoked, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range revoked {
		ev := tokenEvent(audit.PersonalTokenRevoked, t)
		ev.Details["reason"] = reason
		if err := audit.RecordInstance(ctx, tx, actor, ev); err != nil {
			return err
		}
	}
	return nil
}

// RevokePersonalToken révoque le jeton id de userID, avec effet immédiat. Révoquer un jeton
// déjà révoqué ne change rien.
func (s *Service) RevokePersonalToken(ctx context.Context, actor audit.Actor, userID int64, id uuid.UUID) error {
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		t, err := scanPersonalToken(tx.QueryRowContext(ctx, `SELECT `+personalTokenColumns+` FROM personal_access_tokens
			WHERE id = $1 AND user_id = $2 FOR UPDATE`, id, userID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenNotFound
		}
		if err != nil || t.RevokedAt != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE personal_access_tokens SET revoked_at = $2 WHERE id = $1`, id, now()); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, tokenEvent(audit.PersonalTokenRevoked, t))
	})
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return fmt.Errorf("account: révocation d'un jeton personnel : %w", err)
	}
	return err
}

// AuthenticateToken vérifie un jeton personnel présenté à l'API : forme, secret (temps
// constant), révocation, expiration, compte actif, et compte sans mot de passe temporaire
// ni second facteur manquant (un compte réinitialisé n'a plus de jeton actif, mais la
// règle tient même si l'un échappait à la révocation). Un refus est une *TokenError ; le
// jeton n'est jamais journalisé.
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (TokenPrincipal, error) {
	publicID, hash, err := token.Parse(token.Personal, raw)
	if err != nil {
		return TokenPrincipal{}, errTokenInvalid
	}
	var p TokenPrincipal
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		var stored []byte
		var expires time.Time
		var used, revoked sql.NullTime
		var active, mustChange, totp int
		err := tx.QueryRowContext(ctx, `SELECT t.id, t.user_id, t.secret_hash, t.expires_at, t.last_used_at, t.revoked_at,
			       u.email, u.is_active, u.must_change_pwd, coalesce(m.enabled, 0)
			  FROM personal_access_tokens t JOIN users u ON u.id = t.user_id
			  LEFT JOIN mfa_totp m ON m.user_id = t.user_id
			 WHERE t.public_id = $1`, publicID).
			Scan(&p.TokenID, &p.UserID, &stored, &expires, &used, &revoked, &p.Email, &active, &mustChange, &totp)
		if errors.Is(err, sql.ErrNoRows) {
			return errTokenInvalid
		}
		if err != nil {
			return err
		}
		if !hash.Matches(stored) {
			return errTokenInvalid
		}
		at := now()
		switch {
		case revoked.Valid:
			return &TokenError{Key: KeyTokenRevoked}
		case !at.Before(expires):
			return &TokenError{Key: KeyTokenExpired}
		case active != 1:
			return &TokenError{Key: KeyAccountClosed}
		case mustChange != 0 || totp != 1:
			return &TokenError{Key: KeyAccountPending}
		}
		p.PublicID = publicID
		if !used.Valid || at.Sub(used.Time) >= tokenTouchEvery {
			_, err = tx.ExecContext(ctx, `UPDATE personal_access_tokens SET last_used_at = $2 WHERE id = $1`, p.TokenID, at)
		}
		return err
	})
	if err != nil {
		var te *TokenError
		if errors.As(err, &te) {
			return TokenPrincipal{}, te
		}
		return TokenPrincipal{}, fmt.Errorf("account: authentification d'un jeton personnel : %w", err)
	}
	return p, nil
}

// TokenErrorKeys liste les clés de refus des jetons personnels (tests de traduction).
func TokenErrorKeys() []string {
	return []string{KeyTokenInvalid, KeyTokenRevoked, KeyTokenExpired, KeyAccountClosed, KeyAccountPending, KeyTokenLimit}
}
