package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrUnsafeRole : le rôle d'exécution pourrait contourner la RLS.
var ErrUnsafeRole = errors.New("db: rôle d'exécution trop puissant")

// userSchemas exclut les schémas du système dans les requêtes sur le catalogue.
const userSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema')
	AND n.nspname NOT LIKE 'pg\_toast%'
	AND n.nspname NOT LIKE 'pg\_temp\_%'`

// CheckRuntimeRole refuse un rôle d'exécution qui contournerait la RLS : superutilisateur,
// BYPASSRLS, propriétaire d'une relation du schéma, ou membre d'un rôle qui l'est (il
// pourrait en prendre l'identité par SET ROLE). À appeler avec le pool d'exécution, après
// les migrations.
func CheckRuntimeRole(ctx context.Context, q Querier) error {
	var role string
	var super, bypass bool
	if err := q.QueryRowContext(ctx,
		`SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&role, &super, &bypass); err != nil {
		return fmt.Errorf("db: lecture du rôle courant : %w", err)
	}
	var reasons []string
	if super {
		reasons = append(reasons, "superutilisateur")
	}
	if bypass {
		reasons = append(reasons, "attribut BYPASSRLS")
	}
	var powerful string
	if err := q.QueryRowContext(ctx,
		`SELECT coalesce(string_agg(rolname, ', ' ORDER BY rolname), '')
		   FROM pg_roles
		  WHERE (rolsuper OR rolbypassrls) AND rolname <> current_user
		    AND pg_has_role(current_user, oid, 'MEMBER')`,
	).Scan(&powerful); err != nil {
		return fmt.Errorf("db: lecture des appartenances du rôle : %w", err)
	}
	if powerful != "" {
		reasons = append(reasons, "membre de rôles superutilisateurs ou BYPASSRLS ("+powerful+")")
	}
	var owned string
	if err := q.QueryRowContext(ctx,
		`SELECT coalesce(string_agg(n.nspname || '.' || c.relname, ', ' ORDER BY n.nspname, c.relname), '')
		   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE `+userSchemas+`
		    AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
		    AND pg_has_role(current_user, c.relowner, 'MEMBER')`,
	).Scan(&owned); err != nil {
		return fmt.Errorf("db: lecture des propriétaires des tables : %w", err)
	}
	if owned != "" {
		reasons = append(reasons, "propriétaire (directement ou par appartenance) de "+owned)
	}
	if len(reasons) > 0 {
		return fmt.Errorf("%w : %q : %s", ErrUnsafeRole, role, strings.Join(reasons, " ; "))
	}
	return nil
}

// ErrUnprotectedOrgTable : une table d'organisation n'a pas la RLS standard.
var ErrUnprotectedOrgTable = errors.New("db: table d'organisation sans RLS forcée")

// CheckOrgIsolation vérifie, dans le catalogue, que chaque table d'organisation (colonne
// org_id NOT NULL, ou la table organizations) a la RLS activée et forcée, une politique
// pour toutes les commandes fondée sur ogsbom.org_id, et aucune politique permissive qui
// s'en passerait (elle s'ajouterait par OU). Migrate l'exécute avant de valider : une
// migration qui oublie ogsbom_enforce_org_rls empêche le démarrage.
func CheckOrgIsolation(ctx context.Context, q Querier) error {
	const ref = `LIKE '%ogsbom.org_id%'`
	var bad string
	err := q.QueryRowContext(ctx, `
		SELECT coalesce(string_agg(n.nspname || '.' || c.relname, ', ' ORDER BY n.nspname, c.relname), '')
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE `+userSchemas+`
		   AND c.relkind IN ('r', 'p')
		   AND (c.relname = 'organizations' OR EXISTS (
		         SELECT 1 FROM pg_attribute a
		          WHERE a.attrelid = c.oid AND a.attname = 'org_id' AND a.attnotnull AND NOT a.attisdropped))
		   AND NOT (
		         c.relrowsecurity AND c.relforcerowsecurity
		     AND EXISTS (
		         SELECT 1 FROM pg_policy p
		          WHERE p.polrelid = c.oid AND p.polpermissive AND p.polcmd = '*'
		            AND pg_get_expr(p.polqual, p.polrelid) `+ref+`)
		     AND NOT EXISTS (
		         SELECT 1 FROM pg_policy p
		          WHERE p.polrelid = c.oid AND p.polpermissive
		            AND ((p.polqual IS NOT NULL AND pg_get_expr(p.polqual, p.polrelid) NOT `+ref+`)
		              OR (p.polwithcheck IS NOT NULL AND pg_get_expr(p.polwithcheck, p.polrelid) NOT `+ref+`))))`,
	).Scan(&bad)
	if err != nil {
		return fmt.Errorf("db: contrôle de la RLS : %w", err)
	}
	if bad != "" {
		return fmt.Errorf("%w : %s (appeler ogsbom_enforce_org_rls)", ErrUnprotectedOrgTable, bad)
	}
	return nil
}
