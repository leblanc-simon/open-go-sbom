-- 012_search : recherche transverse (T09, § 13 de l'architecture, ADR 0024) et jetons
-- d'accès personnels (ADR 0025).
--
-- La RLS évalue son filtre avant tout opérateur non LEAKPROOF : trigrammes, ILIKE et
-- opérateurs de tableaux (@>) ne peuvent alors servir de condition d'index, et une
-- recherche approchée par nom ou par empreinte lirait tous les composants de
-- l'organisation. Ces deux recherches passent donc par des fonctions SECURITY DEFINER du
-- propriétaire (BYPASSRLS), qui appliquent elles-mêmes la condition de la politique
-- standard (org_id = current_setting('ogsbom.org_id')::uuid) : même périmètre que la RLS,
-- même échec franc hors InOrg, et les index GIN utilisables. Elles ne renvoient que des
-- identifiants de composants de l'organisation déclarée. Le reste de la recherche
-- s'exécute sous la RLS, sur des index B-tree dont les opérateurs (égalité de texte,
-- d'uuid) sont LEAKPROOF.

-- Extensions « trusted » : le propriétaire de la base les crée sans être
-- superutilisateur. Sur une base gérée qui les réserve à un administrateur, les créer
-- avant la migration, dans le schéma public (docs/operations.md).
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS btree_gin WITH SCHEMA public;

-- Nom approché (trigrammes) et nom exact sans casse, toujours sous l'organisation.
CREATE INDEX components_name_trgm_idx ON components USING gin (org_id, name gin_trgm_ops);
CREATE INDEX components_name_lower_idx ON components (org_id, lower(name));
-- Empreintes de fichier (« sha256:<hex> »).
CREATE INDEX components_hashes_idx ON components USING gin (org_id, hashes);

-- Composants dont le nom contient p_query, sans casse ; à défaut, ceux dont le nom lui
-- ressemble (opérateur % de pg_trgm, seuil pg_trgm.similarity_threshold), pour une faute
-- de frappe. En dessous de trois caractères, aucun trigramme ne se forme : nom exact sans
-- casse. Colonne approx : le résultat vient de la ressemblance. Ordre : nom exact
-- d'abord, puis par ressemblance décroissante ; p_limit borné à 1 001 (l'appelant demande
-- une ligne de plus que sa borne pour savoir s'il tronque).
CREATE FUNCTION ogsbom_search_component_names(p_query text, p_limit integer)
RETURNS TABLE (component_id uuid, approx boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    org uuid := current_setting('ogsbom.org_id')::uuid;
    lim integer := greatest(1, least(coalesce(p_limit, 1000), 1001));
    pattern text;
BEGIN
    IF char_length(p_query) < 3 THEN
        RETURN QUERY
            SELECT c.id, false FROM components c
             WHERE c.org_id = org AND lower(c.name) = lower(p_query)
             ORDER BY c.name, c.version, c.id
             LIMIT lim;
        RETURN;
    END IF;
    pattern := '%' || replace(replace(replace(p_query, '\', '\\'), '%', '\%'), '_', '\_') || '%';
    RETURN QUERY
        SELECT c.id, false FROM components c
         WHERE c.org_id = org AND c.name ILIKE pattern
         ORDER BY lower(c.name) = lower(p_query) DESC, similarity(c.name, p_query) DESC, c.name, c.version, c.id
         LIMIT lim;
    IF FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY
        SELECT c.id, true FROM components c
         WHERE c.org_id = org AND c.name % p_query
         ORDER BY similarity(c.name, p_query) DESC, c.name, c.version, c.id
         LIMIT lim;
END
$$;

-- Composants qui portent l'empreinte p_hash (« algorithme:valeur » en minuscules).
CREATE FUNCTION ogsbom_search_component_hashes(p_hash text, p_limit integer)
RETURNS TABLE (component_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT c.id FROM components c
     WHERE c.org_id = current_setting('ogsbom.org_id')::uuid AND c.hashes @> ARRAY[p_hash]
     ORDER BY c.id
     LIMIT greatest(1, least(coalesce(p_limit, 1000), 1001))
$$;

-- Jetons d'accès personnels (ogsbom_pat_…) : une donnée du compte, comme ses sessions, et
-- non d'une organisation. Un jeton ouvre en lecture l'API utilisateur des organisations
-- dont son propriétaire est membre au moment de chaque requête (ADR 0025). Seul le
-- SHA-256 du secret est stocké ; public_id est unique sur l'instance.
CREATE TABLE personal_access_tokens (
    id           uuid PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    public_id    text NOT NULL UNIQUE CHECK (public_id ~ '^[a-z2-7]{26}$'),
    secret_hash  bytea NOT NULL CHECK (length(secret_hash) = 32),
    name         text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    expires_at   timestamptz,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX personal_access_tokens_user_idx ON personal_access_tokens (user_id, created_at DESC, id DESC);
