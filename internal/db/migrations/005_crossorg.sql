-- 005_crossorg : premières lectures inter-organisations (§ 9 de l'architecture, ADR 0012).
--
-- Fonctions SECURITY DEFINER du rôle propriétaire, à search_path fixé, qui ne renvoient
-- que le strict nécessaire. La RLS étant forcée, elles ne lisent au-delà de l'organisation
-- déclarée que parce que le propriétaire a l'attribut BYPASSRLS : il ne lui donne rien
-- de plus, puisqu'il peut déjà désactiver la RLS de ses propres tables. Le rôle
-- d'exécution, lui, ne l'a jamais (contrôle au démarrage). Tout ajout ici est relu comme
-- un changement de sécurité et inscrit dans l'ADR 0012.
DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'le rôle propriétaire % doit avoir l''attribut BYPASSRLS (ALTER ROLE % BYPASSRLS, en superutilisateur) : les fonctions inter-organisations en dépendent', current_user, current_user;
    END IF;
END
$$;

-- Garde d'organisation : l'organisation d'un slug, si le compte en est membre et qu'elle
-- n'est pas archivée ; aucune ligne sinon (la garde répond alors 404, que l'organisation
-- existe ou non).
CREATE FUNCTION ogsbom_org_access(p_slug text, p_user_id bigint)
RETURNS TABLE (org_id uuid, slug text, name text, default_language text, role text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT o.id, o.slug, o.name, o.default_language, m.role
      FROM organizations o
      JOIN org_memberships m ON m.org_id = o.id AND m.user_id = p_user_id
     WHERE o.slug = p_slug AND o.archived_at IS NULL
$$;

-- Sélecteur d'organisation : les organisations actives d'un compte, bornées.
CREATE FUNCTION ogsbom_user_orgs(p_user_id bigint)
RETURNS TABLE (org_id uuid, slug text, name text, role text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT o.id, o.slug, o.name, m.role
      FROM org_memberships m
      JOIN organizations o ON o.id = m.org_id
     WHERE m.user_id = p_user_id AND o.archived_at IS NULL
     ORDER BY o.name, o.slug
     LIMIT 200
$$;

-- Administration de l'instance : la liste des organisations (métadonnées seulement, sans
-- aucune donnée métier), par slug croissant après p_after, au plus p_limit (1 à 200).
-- L'appelant vérifie en Go que le compte est administrateur de l'instance.
CREATE FUNCTION ogsbom_list_organizations(p_after text, p_limit integer)
RETURNS TABLE (org_id uuid, slug text, name text, default_language text,
               archived_at timestamptz, created_at timestamptz, member_count bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT o.id, o.slug, o.name, o.default_language, o.archived_at, o.created_at,
           (SELECT count(*) FROM org_memberships m WHERE m.org_id = o.id)
      FROM organizations o
     WHERE o.slug > coalesce(p_after, '')
     ORDER BY o.slug
     LIMIT greatest(1, least(coalesce(p_limit, 50), 200))
$$;

-- Résolution d'un slug pour l'administration de l'instance (organisations archivées
-- comprises) : son identifiant seulement.
CREATE FUNCTION ogsbom_org_id_by_slug(p_slug text)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT o.id FROM organizations o WHERE o.slug = p_slug
$$;
