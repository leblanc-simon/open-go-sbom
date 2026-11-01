package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/tenant"
)

// Kind est la nature d'un canal.
type Kind string

// Natures de canal.
const (
	KindEmail      Kind = "email"
	KindWebhook    Kind = "webhook"
	KindMatrix     Kind = "matrix"
	KindMattermost Kind = "mattermost"
	KindSlack      Kind = "slack"
)

// Kinds renvoie les natures de canal, dans l'ordre des écrans.
func Kinds() []Kind { return []Kind{KindEmail, KindWebhook, KindMatrix, KindMattermost, KindSlack} }

// Valid indique une nature connue.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

// HasSecret indique si la nature a un secret : clé HMAC du webhook générique, jeton
// Matrix, URL du webhook entrant de Slack ou Mattermost (qui vaut identifiant).
func (k Kind) HasSecret() bool { return k != KindEmail }

// Bornes des canaux.
const (
	MaxChannels   = 50
	MaxRecipients = 20
	maxName       = 100
	maxURL        = 2048
	minHMACSecret = 16
	maxSecret     = 2048
)

// Clés de validation.
const (
	KeyNameInvalid       = "validation.channel_name_invalid"
	KeyNameTaken         = "validation.channel_name_taken"
	KeyKindInvalid       = "validation.channel_kind_invalid"
	KeyRecipientsInvalid = "validation.channel_recipients_invalid"
	KeyURLInvalid        = "validation.channel_url_invalid"
	KeyRoomInvalid       = "validation.channel_room_invalid"
	KeySecretRequired    = "validation.channel_secret_required"
	KeySecretInvalid     = "validation.channel_secret_invalid"
	KeyTooMany           = "validation.channels_too_many"
)

// ErrNotFound : canal inconnu dans l'organisation.
var ErrNotFound = errors.New("notify: canal introuvable")

func invalid(field, key string) error { return &account.ValidationError{Field: field, Key: key} }

// Settings sont les réglages sans secret d'un canal, rangés en jsonb.
type Settings struct {
	Recipients []string `json:"recipients,omitempty"` // e-mail
	URL        string   `json:"url,omitempty"`        // webhook générique
	Homeserver string   `json:"homeserver,omitempty"` // Matrix
	Room       string   `json:"room,omitempty"`       // Matrix : identifiant de salon !x:serveur
}

// Channel est un canal de notification, tel que les écrans l'affichent : son secret
// n'est jamais relu, seule sa présence l'est.
type Channel struct {
	ID            uuid.UUID
	Name          string
	Kind          Kind
	Settings      Settings
	HasSecret     bool
	Enabled       bool
	LastSuccessAt *time.Time
	LastFailureAt *time.Time
	LastErrorKey  string
	Policies      int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Input est la saisie d'un canal. Secret vide à la modification : secret inchangé.
type Input struct {
	Name     string
	Kind     Kind
	Enabled  bool
	Settings Settings
	Secret   string
}

var matrixRoom = regexp.MustCompile(`^![A-Za-z0-9._=\-/+]{1,255}:[A-Za-z0-9.\-]{1,255}(:[0-9]{1,5})?$`)

// cleanName normalise un nom : espaces de bord retirés, sans caractère de contrôle.
func cleanName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	return s, n >= 1 && n <= maxName && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// webURL vérifie une URL http(s) sans identifiants ; https exigé hors développement local
// n'est pas imposé ici : l'envoi refuse les adresses privées (delivery), et un relais
// interne en http reste possible quand l'exploitant l'autorise.
func webURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURL || strings.ContainsFunc(raw, unicode.IsControl) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", false
	}
	return u.String(), true
}

// normalize valide une saisie et la ramène à sa forme rangée. creating : un secret est
// exigé pour une nature qui en a un.
func normalize(in Input, creating bool) (Input, error) {
	name, ok := cleanName(in.Name)
	if !ok {
		return in, invalid("name", KeyNameInvalid)
	}
	out := Input{Name: name, Kind: in.Kind, Enabled: in.Enabled, Secret: strings.TrimSpace(in.Secret)}
	if !in.Kind.Valid() {
		return in, invalid("kind", KeyKindInvalid)
	}
	switch in.Kind {
	case KindEmail:
		seen := map[string]bool{}
		for _, r := range in.Settings.Recipients {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			a, err := mail.ParseAddress(r)
			if err != nil || a.Name != "" || len(a.Address) > 254 || strings.ContainsAny(a.Address, "\r\n") {
				return in, invalid("recipients", KeyRecipientsInvalid)
			}
			addr := strings.ToLower(a.Address)
			if !seen[addr] {
				seen[addr] = true
				out.Settings.Recipients = append(out.Settings.Recipients, a.Address)
			}
		}
		if len(out.Settings.Recipients) == 0 || len(out.Settings.Recipients) > MaxRecipients {
			return in, invalid("recipients", KeyRecipientsInvalid)
		}
		out.Secret = ""
	case KindWebhook:
		u, ok := webURL(in.Settings.URL)
		if !ok {
			return in, invalid("url", KeyURLInvalid)
		}
		out.Settings.URL = u
		if out.Secret != "" && (utf8.RuneCountInString(out.Secret) < minHMACSecret || len(out.Secret) > maxSecret) {
			return in, invalid("secret", KeySecretInvalid)
		}
	case KindMatrix:
		u, ok := webURL(in.Settings.Homeserver)
		if !ok {
			return in, invalid("homeserver", KeyURLInvalid)
		}
		out.Settings.Homeserver = strings.TrimRight(u, "/")
		room := strings.TrimSpace(in.Settings.Room)
		if !matrixRoom.MatchString(room) {
			return in, invalid("room", KeyRoomInvalid)
		}
		out.Settings.Room = room
		if out.Secret != "" && (len(out.Secret) > maxSecret || strings.ContainsFunc(out.Secret, unicode.IsSpace)) {
			return in, invalid("secret", KeySecretInvalid)
		}
	case KindMattermost, KindSlack:
		if out.Secret != "" {
			if _, ok := webURL(out.Secret); !ok {
				return in, invalid("secret", KeySecretInvalid)
			}
		}
	}
	if in.Kind.HasSecret() && creating && out.Secret == "" {
		return in, invalid("secret", KeySecretRequired)
	}
	return out, nil
}

// aad lie le chiffré d'un secret à sa ligne : recopié ailleurs, il ne se déchiffre plus.
func aad(org tenant.OrgID, id uuid.UUID) []byte {
	return []byte("notification_channel:" + org.String() + ":" + id.String())
}

const channelColumns = `c.id, c.name, c.kind, c.settings, c.secret IS NOT NULL, c.enabled, c.last_success_at,
	c.last_failure_at, coalesce(c.last_error_key, ''),
	(SELECT count(*) FROM policy_channels pc WHERE pc.org_id = c.org_id AND pc.channel_id = c.id), c.created_at, c.updated_at`

func scanChannel(row interface{ Scan(...any) error }) (Channel, error) {
	var c Channel
	var settings []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &settings, &c.HasSecret, &c.Enabled, &c.LastSuccessAt, &c.LastFailureAt,
		&c.LastErrorKey, &c.Policies, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Channel{}, err
	}
	if err := json.Unmarshal(settings, &c.Settings); err != nil {
		return Channel{}, fmt.Errorf("notify: réglages du canal %s : %w", c.ID, err)
	}
	return c, nil
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("notify: %s : %w", op, err)
}

func uniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// Channels renvoie les canaux de l'organisation, par nom.
func (s *Service) Channels(ctx context.Context, org tenant.OrgID) ([]Channel, error) {
	var out []Channel
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+channelColumns+` FROM notification_channels c ORDER BY lower(c.name), c.id LIMIT $1`,
			MaxChannels)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanChannel(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	}, db.ReadOnly())
	return out, wrap("liste des canaux", err)
}

// Channel renvoie un canal.
func (s *Service) Channel(ctx context.Context, org tenant.OrgID, id uuid.UUID) (Channel, error) {
	var c Channel
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		c, err = getChannel(ctx, tx, id, false)
		return err
	}, db.ReadOnly())
	return c, wrap("lecture d'un canal", err)
}

func getChannel(ctx context.Context, tx *db.OrgTx, id uuid.UUID, lock bool) (Channel, error) {
	q := `SELECT ` + channelColumns + ` FROM notification_channels c WHERE c.id = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	c, err := scanChannel(tx.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return c, err
}

func channelEvent(action audit.Action, c Input, id uuid.UUID, extra map[string]string) audit.Event {
	details := map[string]string{"kind": string(c.Kind), "enabled": fmt.Sprint(c.Enabled)}
	for k, v := range extra {
		details[k] = v
	}
	return audit.Event{Action: action, TargetType: "channel", TargetID: id.String(), TargetLabel: c.Name, Details: details}
}

func (s *Service) seal(org tenant.OrgID, id uuid.UUID, secret string) ([]byte, string, error) {
	ct, keyID, err := s.o.Secrets.Seal([]byte(secret), aad(org, id))
	if err != nil {
		return nil, "", fmt.Errorf("notify: chiffrement du secret : %w", err)
	}
	return ct, keyID, nil
}

// CreateChannel crée un canal ; son secret est chiffré avant d'entrer en base.
func (s *Service) CreateChannel(ctx context.Context, org tenant.OrgID, actor audit.Actor, in Input) (Channel, error) {
	in, err := normalize(in, true)
	if err != nil {
		return Channel{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Channel{}, err
	}
	settings, err := json.Marshal(in.Settings)
	if err != nil {
		return Channel{}, err
	}
	var ct []byte
	var keyID any
	if in.Secret != "" {
		var k string
		if ct, k, err = s.seal(org, id, in.Secret); err != nil {
			return Channel{}, err
		}
		keyID = k
	}
	now := s.now()
	var c Channel
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_channels`).Scan(&n); err != nil {
			return err
		}
		if n >= MaxChannels {
			return invalid("name", KeyTooMany)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_channels (org_id, id, name, kind, settings, secret,
			secret_key_id, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`,
			tx.OrgID(), id, in.Name, in.Kind, settings, ct, keyID, in.Enabled, now); err != nil {
			if uniqueViolation(err) {
				return invalid("name", KeyNameTaken)
			}
			return err
		}
		if err := audit.RecordOrg(ctx, tx, actor, channelEvent(audit.ChannelCreated, in, id, nil)); err != nil {
			return err
		}
		c, err = getChannel(ctx, tx, id, false)
		return err
	})
	return c, wrap("création d'un canal", err)
}

// UpdateChannel modifie un canal ; un secret vide garde le secret existant, sauf si la
// destination change (serveur Matrix, URL du webhook générique) : le secret doit alors être
// ressaisi (KeySecretRequired). Sans cette règle, un administrateur qui ne connaît pas le
// jeton Matrix le ferait envoyer au serveur de son choix, et un webhook redirigé recevrait
// des messages signés valides (SEC2-04). Réactiver un canal remet en file ses envois en
// attente.
func (s *Service) UpdateChannel(ctx context.Context, org tenant.OrgID, actor audit.Actor, id uuid.UUID, in Input) (Channel, error) {
	in, err := normalize(in, false)
	if err != nil {
		return Channel{}, err
	}
	settings, err := json.Marshal(in.Settings)
	if err != nil {
		return Channel{}, err
	}
	var c Channel
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		old, err := getChannel(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if old.Kind != in.Kind {
			return invalid("kind", KeyKindInvalid)
		}
		changed := map[string]string{}
		if destination(old.Kind, old.Settings) != destination(in.Kind, in.Settings) {
			if in.Secret == "" && old.HasSecret {
				return invalid("secret", KeySecretRequired)
			}
			changed["destination"] = "changed"
		}
		if in.Secret != "" {
			ct, keyID, err := s.seal(org, id, in.Secret)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE notification_channels SET secret = $2, secret_key_id = $3 WHERE id = $1`,
				id, ct, keyID); err != nil {
				return err
			}
			changed["secret"] = "changed"
		} else if in.Kind.HasSecret() && !old.HasSecret {
			return invalid("secret", KeySecretRequired)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notification_channels SET name = $2, settings = $3, enabled = $4,
			updated_at = $5 WHERE id = $1`, id, in.Name, settings, in.Enabled, s.now()); err != nil {
			if uniqueViolation(err) {
				return invalid("name", KeyNameTaken)
			}
			return err
		}
		if in.Enabled && !old.Enabled {
			if err := enqueuePending(ctx, tx, id); err != nil {
				return err
			}
		}
		if err := audit.RecordOrg(ctx, tx, actor, channelEvent(audit.ChannelUpdated, in, id, changed)); err != nil {
			return err
		}
		c, err = getChannel(ctx, tx, id, false)
		return err
	})
	return c, wrap("modification d'un canal", err)
}

// destination renvoie l'adresse à laquelle part le secret d'un canal : serveur Matrix
// (jeton en Authorization), URL du webhook générique (messages signés par la clé). Pour
// Slack et Mattermost, l'URL est le secret lui-même ; l'e-mail n'a pas de secret.
func destination(k Kind, s Settings) string {
	switch k {
	case KindMatrix:
		return s.Homeserver
	case KindWebhook:
		return s.URL
	}
	return ""
}

// DeleteChannel supprime un canal, ses liens aux politiques et ses envois.
func (s *Service) DeleteChannel(ctx context.Context, org tenant.OrgID, actor audit.Actor, id uuid.UUID) error {
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		c, err := getChannel(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, channelEvent(audit.ChannelDeleted,
			Input{Name: c.Name, Kind: c.Kind, Enabled: c.Enabled}, id, nil))
	})
	return wrap("suppression d'un canal", err)
}

// target est ce qu'un envoi lit d'un canal : sa nature, ses réglages et son secret en
// clair, qui ne quitte jamais la mémoire du worker.
type target struct {
	Channel
	secret string
}

func (s *Service) loadTarget(ctx context.Context, tx *db.OrgTx, id uuid.UUID) (target, error) {
	c, err := getChannel(ctx, tx, id, false)
	if err != nil {
		return target{}, err
	}
	t := target{Channel: c}
	if !c.HasSecret {
		return t, nil
	}
	var ct []byte
	var keyID string
	if err := tx.QueryRowContext(ctx, `SELECT secret, secret_key_id FROM notification_channels WHERE id = $1`, id).
		Scan(&ct, &keyID); err != nil {
		return target{}, err
	}
	pt, err := s.o.Secrets.Open(ct, keyID, aad(tx.OrgID(), id))
	if err != nil {
		return target{}, fmt.Errorf("notify: secret du canal %s illisible : %w", id, err)
	}
	t.secret = string(pt)
	return t, nil
}

// RotateSecrets rechiffre avec la clé active les secrets de canaux chiffrés par une autre
// clé, organisation par organisation (liste par crossorg, § 16), et en renvoie le nombre.
// Appelé au démarrage, comme la rotation des secrets TOTP : l'ancienne clé peut être
// retirée au démarrage suivant.
func (s *Service) RotateSecrets(ctx context.Context) (int, error) {
	n := 0
	after := ""
	for {
		var page []crossorg.OrgSummary
		if err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
			var err error
			page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage)
			return err
		}, db.ReadOnly()); err != nil {
			return n, fmt.Errorf("notify: rotation des secrets : %w", err)
		}
		for _, o := range page {
			err := s.o.Pool.InOrg(ctx, o.Org, func(tx *db.OrgTx) error {
				rows, err := tx.QueryContext(ctx, `SELECT id, secret, secret_key_id FROM notification_channels
					WHERE secret IS NOT NULL AND secret_key_id <> $1 FOR UPDATE`, s.o.Secrets.ActiveKeyID())
				if err != nil {
					return err
				}
				type sealed struct {
					id    uuid.UUID
					ct    []byte
					keyID string
				}
				var todo []sealed
				for rows.Next() {
					var x sealed
					if err := rows.Scan(&x.id, &x.ct, &x.keyID); err != nil {
						rows.Close()
						return err
					}
					todo = append(todo, x)
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					return err
				}
				rows.Close()
				for _, x := range todo {
					ct, keyID, err := s.o.Secrets.Rotate(x.ct, x.keyID, aad(tx.OrgID(), x.id))
					if err != nil {
						return fmt.Errorf("canal %s : %w", x.id, err)
					}
					if _, err := tx.ExecContext(ctx, `UPDATE notification_channels SET secret = $2, secret_key_id = $3 WHERE id = $1`,
						x.id, ct, keyID); err != nil {
						return err
					}
					n++
				}
				return nil
			})
			if err != nil {
				return n, fmt.Errorf("notify: rotation des secrets de %s : %w", o.Slug, err)
			}
		}
		if len(page) < crossorg.MaxPage {
			return n, nil
		}
		after = page[len(page)-1].Slug
	}
}
