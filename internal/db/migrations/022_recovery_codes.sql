-- 022_recovery_codes : codes de secours du second facteur (T18, open-go-base v1.4.0).
--
-- La table mfa_recovery_codes est créée par le Migrate de mfax, joué sous le verrou avant
-- les migrations du projet : droits du rôle d'exécution accordés explicitement, comme en
-- 003 et 015. Elle ne porte que des empreintes SHA-256, jamais les codes en clair.
DO $$
DECLARE
    app text := current_setting('lotor.app_role');
BEGIN
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_recovery_codes TO %I', app);
END
$$;
