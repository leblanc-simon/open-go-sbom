package vuln

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
)

// InstanceRetention est la durée au-delà de laquelle la ligne d'une instance restée sans
// nouvelles (tuée sans arrêt propre) est supprimée.
const InstanceRetention = 7 * 24 * time.Hour

// MaxInstances borne la liste des instances de l'écran d'administration.
const MaxInstances = 100

// Instance est l'état rapporté par une instance worker : la base qu'elle a chargée et la
// dernière erreur de synchronisation.
type Instance struct {
	Name string
	// Loaded est la version chargée ; zéro sans base.
	Loaded    Version
	LoadedAt  *time.Time
	SyncError string
	SeenAt    time.Time
}

// defaultInstance nomme l'instance comme le fait jobs pour la colonne worker : hôte et
// PID.
func defaultInstance() string {
	host, _ := os.Hostname()
	return host + ":" + strconv.Itoa(os.Getpid())
}

// report enregistre l'état de l'instance et supprime les lignes trop anciennes.
func (m *Manager) report(ctx context.Context, syncErr error) error {
	now := m.o.Now().Round(time.Microsecond)
	var archive uuid.NullUUID
	var built, loadedAt sql.NullTime
	var schema sql.NullString
	if v, at, ok := m.loadedAt(); ok {
		archive = uuid.NullUUID{UUID: v.ArchiveID, Valid: true}
		built = sql.NullTime{Time: v.Built, Valid: true}
		schema = sql.NullString{String: v.Schema, Valid: true}
		loadedAt = sql.NullTime{Time: at, Valid: true}
	}
	msg := ""
	if syncErr != nil {
		msg = clipText(syncErr.Error(), 500)
	}
	return m.o.Pool.InTx(ctx, func(tx *db.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vulndb_instances (instance, archive_id, built_at, schema, loaded_at, sync_error, seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (instance) DO UPDATE SET archive_id = EXCLUDED.archive_id, built_at = EXCLUDED.built_at,
				schema = EXCLUDED.schema, loaded_at = EXCLUDED.loaded_at, sync_error = EXCLUDED.sync_error,
				seen_at = EXCLUDED.seen_at`,
			m.o.Instance, archive, built, schema, loadedAt, msg, now); err != nil {
			return fmt.Errorf("vuln: état de l'instance : %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM vulndb_instances WHERE seen_at < $1`, now.Add(-InstanceRetention)); err != nil {
			return fmt.Errorf("vuln: purge des instances : %w", err)
		}
		return nil
	})
}

// forget supprime la ligne de l'instance (arrêt propre).
func (m *Manager) forget(ctx context.Context) error {
	if _, err := m.o.Pool.DB().ExecContext(ctx, `DELETE FROM vulndb_instances WHERE instance = $1`, m.o.Instance); err != nil {
		return fmt.Errorf("vuln: retrait de l'instance : %w", err)
	}
	return nil
}

// ListInstances renvoie les instances worker connues, de la plus récemment vue à la plus
// ancienne (MaxInstances au plus).
func ListInstances(ctx context.Context, q db.Querier) ([]Instance, error) {
	rows, err := q.QueryContext(ctx, `SELECT instance, archive_id, built_at, schema, loaded_at, sync_error, seen_at
		FROM vulndb_instances ORDER BY seen_at DESC, instance LIMIT $1`, MaxInstances)
	if err != nil {
		return nil, fmt.Errorf("vuln: instances : %w", err)
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var in Instance
		var archive uuid.NullUUID
		var built, loadedAt sql.NullTime
		var schema sql.NullString
		if err := rows.Scan(&in.Name, &archive, &built, &schema, &loadedAt, &in.SyncError, &in.SeenAt); err != nil {
			return nil, fmt.Errorf("vuln: instances : %w", err)
		}
		in.SeenAt = in.SeenAt.UTC()
		if archive.Valid {
			in.Loaded = Version{ArchiveID: archive.UUID, Built: built.Time.UTC(), Schema: schema.String}
			t := loadedAt.Time.UTC()
			in.LoadedAt = &t
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// clipText coupe s à n octets au plus, sur une frontière de caractère.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
