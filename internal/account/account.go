package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/open-go-base/authx"

	"leblanc.io/open-go-sbom/internal/audit"
	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/pagination"
)

// RoleAdmin est le rôle d'instance (colonne role d'authx) de l'administrateur d'instance.
// Un compte ordinaire a un rôle vide.
const RoleAdmin authx.Role = "admin"

var (
	// ErrNotFound : compte inconnu.
	ErrNotFound = errors.New("account: compte inconnu")
)

// User est un compte tel que l'administration le présente.
type User struct {
	ID            int64
	Email         string
	Admin         bool
	Active        bool
	MustChangePwd bool
	TOTPEnabled   bool
	CreatedAt     time.Time
	LastLogin     *time.Time
}

// Service crée et modifie les comptes. C'est le seul écrivain de la table users d'authx ;
// chaque modification est journalisée dans la même transaction.
type Service struct {
	pool       *db.Pool
	bcryptCost int
}

// NewService construit le service. bcryptCost est celui d'appconf.Auth.
func NewService(pool *db.Pool, bcryptCost int) *Service {
	return &Service{pool: pool, bcryptCost: bcryptCost}
}

const userColumns = `u.id, u.email, u.role, u.is_active, u.must_change_pwd, u.created_at, u.last_login,
	coalesce(t.enabled, 0)`

const userFrom = ` FROM users u LEFT JOIN mfa_totp t ON t.user_id = u.id`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var role string
	var active, mustChange, totp int
	var last sql.NullTime
	if err := row.Scan(&u.ID, &u.Email, &role, &active, &mustChange, &u.CreatedAt, &last, &totp); err != nil {
		return User{}, err
	}
	u.Admin = authx.Role(role) == RoleAdmin
	u.Active, u.MustChangePwd, u.TOTPEnabled = active == 1, mustChange == 1, totp == 1
	if last.Valid {
		t := last.Time
		u.LastLogin = &t
	}
	return u, nil
}

func getUser(ctx context.Context, q db.Querier, id int64, lock bool) (User, error) {
	query := `SELECT ` + userColumns + userFrom + ` WHERE u.id = $1`
	if lock {
		query += ` FOR UPDATE OF u`
	}
	u, err := scanUser(q.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("account: lecture du compte %d : %w", id, err)
	}
	return u, nil
}

// Get renvoie un compte.
func (s *Service) Get(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		u, err = getUser(ctx, tx, id, false)
		return err
	}, db.ReadOnly())
	return u, err
}

// GetByEmail renvoie le compte d'un e-mail (forme normalisée).
func (s *Service) GetByEmail(ctx context.Context, email string) (User, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return User{}, ErrNotFound
	}
	var u User
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		var err error
		u, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+userFrom+` WHERE u.email = $1`, e))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return u, err
}

// DefaultPage et MaxPage bornent une page de comptes.
const (
	DefaultPage = 50
	MaxPage     = 200
)

// List renvoie une page de comptes par e-mail croissant.
func (s *Service) List(ctx context.Context, cursor string, limit int) (pagination.Page[User], error) {
	if limit < 1 || limit > MaxPage {
		return pagination.Page[User]{}, &pagination.LimitError{Max: MaxPage}
	}
	var after string
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[User]{}, err
		}
	}
	var page pagination.Page[User]
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT `+userColumns+userFrom+` WHERE u.email > $1 ORDER BY u.email LIMIT $2`, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var out []User
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		page, err = pagination.Build(out, limit, func(u User) any { return u.Email })
		return err
	}, db.ReadOnly())
	if err != nil {
		return pagination.Page[User]{}, fmt.Errorf("account: liste des comptes : %w", err)
	}
	return page, nil
}

// ActiveAdmins compte les administrateurs d'instance actifs.
func (s *Service) ActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT count(*) FROM users WHERE role = $1 AND is_active = 1`, string(RoleAdmin)).Scan(&n)
	}, db.ReadOnly())
	if err != nil {
		return 0, fmt.Errorf("account: décompte des administrateurs : %w", err)
	}
	return n, nil
}

func target(u User) audit.Event {
	return audit.Event{TargetType: "account", TargetID: strconv.FormatInt(u.ID, 10), TargetLabel: u.Email}
}

func event(action audit.Action, u User, details map[string]string) audit.Event {
	e := target(u)
	e.Action = action
	e.Details = details
	return e
}

// Create crée un compte avec un mot de passe temporaire, à changer à la première connexion
// (must_change_pwd), et renvoie ce mot de passe, à transmettre une fois au titulaire.
func (s *Service) Create(ctx context.Context, actor audit.Actor, email string, admin bool) (User, string, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return User{}, "", err
	}
	password := GeneratePassword()
	u, err := s.create(ctx, actor, e, password, admin, audit.AccountCreated)
	return u, password, err
}

func (s *Service) create(ctx context.Context, actor audit.Actor, email, password string, admin bool, action audit.Action) (User, error) {
	if err := ValidatePassword(password, email); err != nil {
		return User{}, err
	}
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return User{}, fmt.Errorf("account: hachage : %w", err)
	}
	role := ""
	if admin {
		role = string(RoleAdmin)
	}
	var u User
	err = s.pool.InTx(ctx, func(tx *db.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx,
			`INSERT INTO users (email, password_hash, role, must_change_pwd) VALUES ($1, $2, $3, 1) RETURNING id`,
			email, hash, role).Scan(&id)
		if isUniqueViolation(err) {
			return &ValidationError{Field: "email", Key: KeyEmailTaken}
		}
		if err != nil {
			return err
		}
		if u, err = getUser(ctx, tx, id, false); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, event(action, u, map[string]string{"admin": strconv.FormatBool(admin)}))
	})
	if err != nil {
		if _, ok := IsValidation(err); ok {
			return User{}, err
		}
		return User{}, fmt.Errorf("account: création de %s : %w", email, err)
	}
	return u, nil
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// update charge le compte id sous verrou, applique change dans la transaction puis
// journalise l'événement qu'il renvoie.
func (s *Service) update(ctx context.Context, actor audit.Actor, id int64, change func(*db.Tx, User) (audit.Event, error)) error {
	return s.pool.InTx(ctx, func(tx *db.Tx) error {
		u, err := getUser(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev, err := change(tx, u)
		if err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, actor, ev)
	})
}

// lastAdminGuard refuse de retirer le dernier administrateur d'instance actif.
func lastAdminGuard(ctx context.Context, tx *db.Tx, u User) error {
	if !u.Admin || !u.Active {
		return nil
	}
	var others int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM users WHERE role = $1 AND is_active = 1 AND id <> $2`, string(RoleAdmin), u.ID,
	).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return &ValidationError{Field: "account", Key: KeyLastAdmin}
	}
	return nil
}

func deleteSessions(ctx context.Context, tx *db.Tx, userID int64, keepToken string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token <> $2`, userID, keepToken)
	return err
}

// SetActive active ou désactive un compte ; la désactivation ferme ses sessions. Le
// dernier administrateur d'instance actif ne peut pas être désactivé.
func (s *Service) SetActive(ctx context.Context, actor audit.Actor, id int64, active bool) error {
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if !active {
			if actor.UserID == u.ID {
				return audit.Event{}, &ValidationError{Field: "account", Key: KeyCannotTargetSelf}
			}
			if err := lastAdminGuard(ctx, tx, u); err != nil {
				return audit.Event{}, err
			}
			if err := deleteSessions(ctx, tx, u.ID, ""); err != nil {
				return audit.Event{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET is_active = $1 WHERE id = $2`, boolInt(active), u.ID); err != nil {
			return audit.Event{}, err
		}
		action := audit.AccountActivated
		if !active {
			action = audit.AccountDeactivated
		}
		return event(action, u, nil), nil
	})
}

// SetAdmin promeut un compte administrateur d'instance ou lui retire ce rôle ; le dernier
// administrateur actif le garde.
func (s *Service) SetAdmin(ctx context.Context, actor audit.Actor, id int64, admin bool) error {
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if !admin {
			if err := lastAdminGuard(ctx, tx, u); err != nil {
				return audit.Event{}, err
			}
		}
		role := ""
		if admin {
			role = string(RoleAdmin)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET role = $1 WHERE id = $2`, role, u.ID); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountRoleChanged, u, map[string]string{"admin": strconv.FormatBool(admin)}), nil
	})
}

// ResetPassword remplace le mot de passe d'un compte par un mot de passe temporaire (à
// changer à la connexion suivante), ferme ses sessions et renvoie le mot de passe.
func (s *Service) ResetPassword(ctx context.Context, actor audit.Actor, id int64) (string, error) {
	password := GeneratePassword()
	hash, err := authx.HashPassword(password, s.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("account: hachage : %w", err)
	}
	err = s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = $1, must_change_pwd = 1 WHERE id = $2`, hash, u.ID); err != nil {
			return audit.Event{}, err
		}
		if err := deleteSessions(ctx, tx, u.ID, ""); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountPasswordReset, u, nil), nil
	})
	if err != nil {
		return "", err
	}
	return password, nil
}

// ResetTOTP retire le second facteur d'un compte et ferme ses sessions : il enrôlera un
// nouveau TOTP à sa prochaine connexion.
func (s *Service) ResetTOTP(ctx context.Context, actor audit.Actor, id int64) error {
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if err := resetTOTP(ctx, tx, u.ID); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountTOTPReset, u, nil), nil
	})
}

func resetTOTP(ctx context.Context, tx *db.Tx, userID int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return deleteSessions(ctx, tx, userID, "")
}

// ChangePassword change le mot de passe d'un compte après vérification de l'actuel, lève
// must_change_pwd et ferme ses autres sessions (keepToken est le jeton de la session
// courante, conservée).
func (s *Service) ChangePassword(ctx context.Context, actor audit.Actor, id int64, current, next, confirm, keepToken string) error {
	if next != confirm {
		return &ValidationError{Field: "confirm", Key: KeyPasswordMismatch}
	}
	var hash, email string
	err := s.pool.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT password_hash, email FROM users WHERE id = $1`, id).Scan(&hash, &email)
	}, db.ReadOnly())
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("account: lecture du compte %d : %w", id, err)
	}
	if err := authx.CheckPassword(hash, current); err != nil {
		if errors.Is(err, authx.ErrInvalidCredentials) {
			return &ValidationError{Field: "current", Key: KeyPasswordWrong}
		}
		return fmt.Errorf("account: vérification du mot de passe : %w", err)
	}
	if err := ValidatePassword(next, email); err != nil {
		return err
	}
	if next == current {
		return &ValidationError{Field: "password", Key: KeyPasswordUnchanged}
	}
	newHash, err := authx.HashPassword(next, s.bcryptCost)
	if err != nil {
		return fmt.Errorf("account: hachage : %w", err)
	}
	return s.update(ctx, actor, id, func(tx *db.Tx, u User) (audit.Event, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = $1, must_change_pwd = 0 WHERE id = $2`, newHash, u.ID); err != nil {
			return audit.Event{}, err
		}
		if err := deleteSessions(ctx, tx, u.ID, keepToken); err != nil {
			return audit.Event{}, err
		}
		return event(audit.AccountPasswordChanged, u, nil), nil
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
