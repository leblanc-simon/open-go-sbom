-- 001_init : droits du rôle d'exécution et outil de RLS standard.
--
-- Exécutée par le rôle propriétaire, dans la transaction du verrou de migration.
-- L'exécuteur déclare le rôle d'exécution dans ogsbom.app_role (portée transaction).

-- Privilèges par défaut sur les objets que le propriétaire créera ensuite : le rôle
-- d'exécution lit et écrit les données, sans DDL, TRUNCATE, REFERENCES ni TRIGGER.
-- Sans IN SCHEMA, car le retrait d'EXECUTE à PUBLIC n'a d'effet qu'au niveau global.
DO $$
DECLARE
    app text := current_setting('ogsbom.app_role');
BEGIN
    IF app = '' THEN
        RAISE EXCEPTION 'ogsbom.app_role est vide';
    END IF;
    EXECUTE format('ALTER DEFAULT PRIVILEGES GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', app);
    EXECUTE format('ALTER DEFAULT PRIVILEGES GRANT USAGE, SELECT ON SEQUENCES TO %I', app);
    ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    EXECUTE format('ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO %I', app);
END
$$;

-- Politique standard d'une table d'organisation (§ 9 de l'architecture) : RLS activée et
-- forcée (le propriétaire y est soumis aussi), lecture et écriture limitées à
-- l'organisation déclarée par db.InOrg. Sans organisation déclarée, current_setting
-- échoue (paramètre absent) ou la conversion de '' en uuid échoue : jamais zéro ligne en
-- silence. Pour la table organizations, la colonne est id.
CREATE PROCEDURE ogsbom_enforce_org_rls(tbl regclass, col name DEFAULT 'org_id')
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
        'CREATE POLICY org_isolation ON %s'
        ' USING (%I = current_setting(''ogsbom.org_id'')::uuid)'
        ' WITH CHECK (%I = current_setting(''ogsbom.org_id'')::uuid)',
        tbl, col, col);
END
$$;

-- Outil de migration seulement : le rôle d'exécution n'a pas à l'appeler.
DO $$
BEGIN
    EXECUTE format('REVOKE EXECUTE ON PROCEDURE ogsbom_enforce_org_rls(regclass, name) FROM %I',
        current_setting('ogsbom.app_role'));
END
$$;
