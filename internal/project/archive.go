package project

import (
	"context"
	"fmt"
	"time"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/tenant"
)

// Types des jobs d'archivage des conteneurs absents.
const (
	// ArchiveAllKind met en file un ArchiveOrgKind par organisation active.
	ArchiveAllKind = "project.archive_containers_all"
	// ArchiveOrgKind archive les conteneurs absents d'une organisation.
	ArchiveOrgKind = "project.archive_containers"
)

// ArchiveEvery espace les passages de l'archivage : l'absence se compte en jours.
const ArchiveEvery = time.Hour

// DefaultArchiveAfter est l'absence au-delà de laquelle un conteneur est archivé
// (décision du 1er novembre 2026 : 7 jours, réglable par containers.archive_after).
const DefaultArchiveAfter = 7 * 24 * time.Hour

// Archiver archive les projets des conteneurs que l'agent de leur hôte n'a plus signalés
// depuis After.
type Archiver struct {
	pool  *db.Pool
	after time.Duration
	now   func() time.Time
}

// NewArchiver construit l'archiveur ; now nil prend l'horloge du système.
func NewArchiver(pool *db.Pool, after time.Duration, now func() time.Time) *Archiver {
	if now == nil {
		now = time.Now
	}
	if after <= 0 {
		after = DefaultArchiveAfter
	}
	return &Archiver{pool: pool, after: after, now: now}
}

// Schedule est l'échéance de l'archivage.
func (a *Archiver) Schedule() jobs.Schedule {
	return jobs.Schedule{Name: ArchiveAllKind, Every: ArchiveEvery, Job: jobs.Job{Kind: ArchiveAllKind, Priority: jobs.PriorityLow}}
}

// AllHandler est le handler d'ArchiveAllKind : un job par organisation active, listées
// par crossorg (§ 16).
func (a *Archiver) AllHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		after := ""
		for {
			var page []crossorg.OrgSummary
			err := a.pool.InTx(ctx, func(tx *db.Tx) error {
				var err error
				if page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage); err != nil {
					return err
				}
				for _, o := range page {
					if o.ArchivedAt != nil {
						continue
					}
					if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: ArchiveOrgKind, OrgID: o.Org, Priority: jobs.PriorityLow,
						UniqueKey: "org:" + o.Org.String()}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("project: archivage des conteneurs du parc : %w", err)
			}
			if len(page) < crossorg.MaxPage {
				return nil
			}
			after = page[len(page)-1].Slug
		}
	})
}

// OrgHandler est le handler d'ArchiveOrgKind.
func (a *Archiver) OrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(fmt.Errorf("project: %s sans organisation", ArchiveOrgKind))
		}
		_, err := a.Archive(ctx, e.OrgID)
		return err
	})
}

// Archive archive les conteneurs absents depuis After dans org et en renvoie le nombre.
// Idempotent : un second passage ne trouve plus rien.
func (a *Archiver) Archive(ctx context.Context, org tenant.OrgID) (int, error) {
	now := a.now().UTC()
	var n int
	err := a.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		n, err = ArchiveAbsent(ctx, tx, now.Add(-a.after), now)
		return err
	})
	return n, err
}
