package crossorg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"leblanc.io/open-go-sbom/internal/db"
	"leblanc.io/open-go-sbom/internal/tenant"
)

// ErrNoAccess : organisation inconnue, archivée, ou dont le compte n'est pas membre. Les
// trois cas sont volontairement confondus (la garde répond 404).
var ErrNoAccess = errors.New("crossorg: organisation inaccessible")

// ErrNotFound : aucune organisation ne porte ce slug.
var ErrNotFound = errors.New("crossorg: organisation inconnue")

// MaxPage borne une page de ListOrganizations.
const MaxPage = 200

// Access résout le slug d'une organisation active dont userID est membre, pour la garde
// d'organisation (fonction ogsbom_org_access).
func Access(ctx context.Context, q db.Querier, slug string, userID int64) (tenant.Access, error) {
	var a tenant.Access
	var role string
	err := q.QueryRowContext(ctx,
		`SELECT org_id, slug, name, default_language, role FROM ogsbom_org_access($1, $2)`, slug, userID,
	).Scan(&a.Org, &a.Slug, &a.Name, &a.Language, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant.Access{}, ErrNoAccess
	}
	if err != nil {
		return tenant.Access{}, fmt.Errorf("crossorg: accès à %q : %w", slug, err)
	}
	if a.Role, err = tenant.ParseRole(role); err != nil {
		return tenant.Access{}, err
	}
	return a, nil
}

// OrgRef est une organisation du sélecteur.
type OrgRef struct {
	Org  tenant.OrgID
	Slug string
	Name string
	Role tenant.Role
}

// UserOrgs renvoie les organisations actives de userID, par nom (200 au plus ; fonction
// ogsbom_user_orgs).
func UserOrgs(ctx context.Context, q db.Querier, userID int64) ([]OrgRef, error) {
	rows, err := q.QueryContext(ctx, `SELECT org_id, slug, name, role FROM ogsbom_user_orgs($1)`, userID)
	if err != nil {
		return nil, fmt.Errorf("crossorg: organisations du compte : %w", err)
	}
	defer rows.Close()
	var out []OrgRef
	for rows.Next() {
		var o OrgRef
		var role string
		if err := rows.Scan(&o.Org, &o.Slug, &o.Name, &role); err != nil {
			return nil, fmt.Errorf("crossorg: organisations du compte : %w", err)
		}
		if o.Role, err = tenant.ParseRole(role); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crossorg: organisations du compte : %w", err)
	}
	return out, nil
}

// OrgSummary décrit une organisation pour l'administration de l'instance.
type OrgSummary struct {
	Org             tenant.OrgID
	Slug            string
	Name            string
	DefaultLanguage string
	ArchivedAt      *time.Time
	CreatedAt       time.Time
	Members         int64
}

// ListOrganizations renvoie au plus limit organisations (archivées comprises) de slug
// supérieur à after, par slug (fonction ogsbom_list_organizations). Réservé à
// l'administration de l'instance : l'appelant vérifie le rôle du compte.
func ListOrganizations(ctx context.Context, q db.Querier, after string, limit int) ([]OrgSummary, error) {
	if limit < 1 || limit > MaxPage {
		return nil, fmt.Errorf("crossorg: taille de page %d hors de [1, %d]", limit, MaxPage)
	}
	rows, err := q.QueryContext(ctx,
		`SELECT org_id, slug, name, default_language, archived_at, created_at, member_count
		   FROM ogsbom_list_organizations($1, $2)`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("crossorg: liste des organisations : %w", err)
	}
	defer rows.Close()
	var out []OrgSummary
	for rows.Next() {
		var o OrgSummary
		var archived sql.NullTime
		if err := rows.Scan(&o.Org, &o.Slug, &o.Name, &o.DefaultLanguage, &archived, &o.CreatedAt, &o.Members); err != nil {
			return nil, fmt.Errorf("crossorg: liste des organisations : %w", err)
		}
		if archived.Valid {
			t := archived.Time
			o.ArchivedAt = &t
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crossorg: liste des organisations : %w", err)
	}
	return out, nil
}

// OrgIDBySlug résout un slug, organisations archivées comprises, pour l'administration de
// l'instance (fonction ogsbom_org_id_by_slug).
func OrgIDBySlug(ctx context.Context, q db.Querier, slug string) (tenant.OrgID, error) {
	var id sql.Null[tenant.OrgID]
	if err := q.QueryRowContext(ctx, `SELECT ogsbom_org_id_by_slug($1)`, slug).Scan(&id); err != nil {
		return tenant.OrgID{}, fmt.Errorf("crossorg: slug %q : %w", slug, err)
	}
	if !id.Valid {
		return tenant.OrgID{}, ErrNotFound
	}
	return id.V, nil
}
