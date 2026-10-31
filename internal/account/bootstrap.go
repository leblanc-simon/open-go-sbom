package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"leblanc.io/open-go-base/authx"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
)

// startupLockKey sérialise bootstrap et procédure de secours entre instances qui démarrent
// ensemble (verrou consultatif de transaction, compatible avec pgbouncer).
const startupLockKey int64 = 0x6f6773626f6d02 // « ogsbom » + 2

// MinRescueTicket est la longueur minimale du ticket de la procédure de secours.
const MinRescueTicket = 8

var (
	// ErrRescueNotAdmin : la procédure de secours ne vaut que pour un administrateur
	// d'instance actif.
	ErrRescueNotAdmin = errors.New("account: la procédure de secours ne s'applique qu'à un administrateur d'instance actif")
)

// Bootstrap crée le premier administrateur d'instance si aucun compte n'existe ; il est
// ignoré (created faux) dès qu'un compte existe. Le mot de passe fourni doit respecter la
// politique et sera changé à la première connexion (must_change_pwd), avec l'enrôlement
// TOTP.
func (s *Service) Bootstrap(ctx context.Context, email, password string) (created bool, err error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return false, err
	}
	if err := ValidatePassword(password, e); err != nil {
		return false, err
	}
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return false, fmt.Errorf("account: hachage : %w", err)
	}
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, startupLockKey); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
		var id int64
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO users (email, password_hash, role, must_change_pwd) VALUES ($1, $2, $3, 1) RETURNING id`,
			e, hash, string(RoleAdmin)).Scan(&id); err != nil {
			return err
		}
		created = true
		return audit.RecordInstance(ctx, tx, audit.System, audit.Event{
			Action: audit.AccountBootstrapped, TargetType: "account", TargetID: strconv.FormatInt(id, 10), TargetLabel: e,
		})
	})
	if err != nil {
		return false, fmt.Errorf("account: premier administrateur : %w", err)
	}
	return created, nil
}

// RescueTOTP est la procédure de secours d'un administrateur d'instance qui a perdu son
// TOTP : elle retire son second facteur, lui impose le mot de passe temporaire password
// (choisi par l'exploitant, changé à la connexion suivante), ferme ses sessions et
// révoque ses jetons personnels, une seule fois par couple (compte, ticket). Sans nouveau
// mot de passe, quiconque connaît l'ancien enrôlerait son propre TOTP (ADR 0029). Le
// ticket (numéro d'incident, date…) est choisi par l'exploitant ; s'il reste en
// configuration, les démarrages suivants n'ont aucun effet (applied faux).
func (s *Service) RescueTOTP(ctx context.Context, email, ticket, password string) (applied bool, err error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return false, err
	}
	ticket = strings.TrimSpace(ticket)
	if utf8.RuneCountInString(ticket) < MinRescueTicket || len(ticket) > 128 {
		return false, &ValidationError{Field: "ticket", Key: KeyRescueTicketTooShort}
	}
	if err := ValidatePassword(password, e); err != nil {
		return false, err
	}
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return false, fmt.Errorf("account: hachage : %w", err)
	}
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, startupLockKey); err != nil {
			return err
		}
		var id int64
		var role string
		var active int
		err := tx.QueryRowContext(ctx, `SELECT id, role, is_active FROM users WHERE email = $1 FOR UPDATE`, e).Scan(&id, &role, &active)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRescueNotAdmin
		}
		if err != nil {
			return err
		}
		if authx.Role(role) != RoleAdmin || active != 1 {
			return ErrRescueNotAdmin
		}
		var done bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM instance_audit_events
			                WHERE action = $1 AND target_id = $2 AND details->>'ticket' = $3)`,
			string(audit.AccountRescueTOTPReset), strconv.FormatInt(id, 10), ticket).Scan(&done); err != nil {
			return err
		}
		if done {
			return nil
		}
		if err := setTemporaryPassword(ctx, tx, id, hash); err != nil {
			return err
		}
		if err := resetTOTP(ctx, tx, audit.System, id); err != nil {
			return err
		}
		applied = true
		return audit.RecordInstance(ctx, tx, audit.System, audit.Event{
			Action: audit.AccountRescueTOTPReset, TargetType: "account", TargetID: strconv.FormatInt(id, 10),
			TargetLabel: e, Details: map[string]string{"ticket": ticket},
		})
	})
	if err != nil {
		if errors.Is(err, ErrRescueNotAdmin) {
			return false, err
		}
		return false, fmt.Errorf("account: procédure de secours : %w", err)
	}
	return applied, nil
}
