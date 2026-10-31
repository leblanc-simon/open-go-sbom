-- 007_crossorg_tokens : résolution de l'organisation d'un jeton d'agent ou d'inscription
-- (§ 9 de l'architecture, ADR 0012). Côté agent, l'organisation vient du jeton : avant de
-- pouvoir ouvrir InOrg, le serveur doit savoir à quelle organisation appartient
-- l'identifiant public présenté.
--
-- Ces fonctions ne renvoient que l'organisation, et seulement si elle est active ; elles ne
-- lisent ni le secret, ni l'état du jeton : la vérification du secret, de la révocation
-- et de l'expiration se fait ensuite dans InOrg, sous la RLS. L'identifiant public est un
-- tirage aléatoire de 128 bits, que l'on ne peut pas deviner : la fonction ne révèle rien
-- à qui ne détient pas déjà le jeton.

CREATE FUNCTION lotor_agent_token_org(p_public_id text)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT t.org_id
      FROM agent_tokens t
      JOIN organizations o ON o.id = t.org_id
     WHERE t.public_id = p_public_id AND o.archived_at IS NULL
$$;

CREATE FUNCTION lotor_enrollment_token_org(p_public_id text)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT t.org_id
      FROM enrollment_tokens t
      JOIN organizations o ON o.id = t.org_id
     WHERE t.public_id = p_public_id AND o.archived_at IS NULL
$$;
