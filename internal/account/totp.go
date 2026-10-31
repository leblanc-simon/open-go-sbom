package account

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"leblanc.io/open-go-base/mfax"

	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/secret"
)

// sealedPrefix marque un secret TOTP chiffré : « s1:<clé>:<chiffré en base64> ».
const sealedPrefix = "s1"

// ErrUnsealedTOTP : la base contient un secret TOTP en clair ou illisible.
var ErrUnsealedTOTP = errors.New("account: secret TOTP non chiffré ou illisible")

// SealedTOTPStore enveloppe le TOTPStore de mfax : les secrets sont chiffrés par
// internal/secret avant d'entrer en base (une lecture de la base ne suffit pas à produire
// des codes) ; l'activation d'un TOTP est journalisée.
type SealedTOTPStore struct {
	mfax.TOTPStore
	box  *secret.Box
	pool *db.Pool
}

// NewSealedTOTPStore enveloppe inner.
func NewSealedTOTPStore(inner mfax.TOTPStore, box *secret.Box, pool *db.Pool) *SealedTOTPStore {
	return &SealedTOTPStore{TOTPStore: inner, box: box, pool: pool}
}

// Les données associées lient le chiffré à son compte : il ne se déplace pas sur un autre.
func totpAAD(userID int64) []byte { return []byte("mfa_totp:" + strconv.FormatInt(userID, 10)) }

func seal(box *secret.Box, userID int64, plain string) (string, error) {
	ct, keyID, err := box.Seal([]byte(plain), totpAAD(userID))
	if err != nil {
		return "", err
	}
	return sealedPrefix + ":" + keyID + ":" + base64.StdEncoding.EncodeToString(ct), nil
}

func unseal(box *secret.Box, userID int64, stored string) (plain, keyID string, err error) {
	parts := strings.SplitN(stored, ":", 3)
	if len(parts) != 3 || parts[0] != sealedPrefix {
		return "", "", ErrUnsealedTOTP
	}
	ct, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", ErrUnsealedTOTP
	}
	p, err := box.Open(ct, parts[1], totpAAD(userID))
	if err != nil {
		return "", "", fmt.Errorf("%w : %w", ErrUnsealedTOTP, err)
	}
	return string(p), parts[1], nil
}

// Get déchiffre le secret.
func (s *SealedTOTPStore) Get(userID int64) (*mfax.TOTP, error) {
	t, err := s.TOTPStore.Get(userID)
	if err != nil {
		return nil, err
	}
	plain, _, err := unseal(s.box, userID, t.Secret)
	if err != nil {
		return nil, err
	}
	out := *t
	out.Secret = plain
	return &out, nil
}

// Set chiffre le secret ; l'activation (enabled) est journalisée.
func (s *SealedTOTPStore) Set(userID int64, plain string, enabled bool) error {
	stored, err := seal(s.box, userID, plain)
	if err != nil {
		return err
	}
	if err := s.TOTPStore.Set(userID, stored, enabled); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	return s.pool.InTx(ctx, func(tx *db.Tx) error {
		var email string
		if err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
			return err
		}
		return audit.RecordInstance(ctx, tx, audit.Actor{UserID: userID, Email: email},
			audit.Event{Action: audit.TOTPEnrolled, TargetType: "account", TargetID: strconv.FormatInt(userID, 10), TargetLabel: email})
	})
}

// RotateTOTPSecrets rechiffre avec la clé active les secrets TOTP chiffrés par une autre
// clé, et renvoie leur nombre. Le serveur l'exécute au démarrage : une ancienne clé peut
// être retirée de la configuration dès le démarrage suivant (docs/operations.md).
func RotateTOTPSecrets(ctx context.Context, pool *db.Pool, box *secret.Box) (int, error) {
	n := 0
	err := pool.InTx(ctx, func(tx *db.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT user_id, secret FROM mfa_totp WHERE secret NOT LIKE $1 ORDER BY user_id FOR UPDATE`,
			sealedPrefix+":"+strings.ReplaceAll(box.ActiveKeyID(), "_", `\_`)+":%")
		if err != nil {
			return err
		}
		type row struct {
			id     int64
			stored string
		}
		var todo []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.stored); err != nil {
				rows.Close()
				return err
			}
			todo = append(todo, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range todo {
			plain, _, err := unseal(box, r.id, r.stored)
			if err != nil {
				return fmt.Errorf("compte %d : %w", r.id, err)
			}
			sealed, err := seal(box, r.id, plain)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE mfa_totp SET secret = $1 WHERE user_id = $2`, sealed, r.id); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("account: rechiffrement des secrets TOTP : %w", err)
	}
	return n, nil
}
