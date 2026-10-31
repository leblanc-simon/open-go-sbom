-- 015_security_hardening : suites de la revue de sécurité du lot 1 (T11, ADR 0030).
--
-- Exécutée par le rôle propriétaire, dans la transaction du verrou de migration.
DO $$
DECLARE
    app text := current_setting('ogsbom.app_role');
BEGIN
    -- Verrouillage par compte de mfax (table mfa_lockouts, créée par son Migrate avant
    -- les migrations du projet) : droits accordés explicitement, comme en 003.
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_lockouts TO %I', app);
    -- Journaux d'audit en ajout seul : le rôle d'exécution y écrit et les lit, mais ne
    -- peut ni modifier ni effacer une entrée (CheckRuntimeRole le vérifie au démarrage).
    -- Les actions des clés étrangères (ON DELETE SET NULL, CASCADE) s'exécutent avec les
    -- droits du propriétaire de la table.
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, instance_audit_events FROM %I', app);
END
$$;

-- Aucun rôle ne crée d'objet dans public hors du propriétaire : un objet du rôle
-- d'exécution y échapperait à la RLS, et public figure dans le search_path des fonctions
-- SECURITY DEFINER. Défaut de PostgreSQL 15 et suivants, imposé ici pour les bases plus
-- anciennes ou modifiées.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
