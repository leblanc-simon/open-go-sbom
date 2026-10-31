-- 003_accounts : droits sur les tables d'authx et de mfax, préférences des comptes,
-- méthode d'authentification des sessions, journal d'audit de l'instance.
--
-- Les tables d'authx et de mfax sont créées par leur Migrate, joué sous le verrou avant
-- les migrations du projet. Sur une base neuve, elles précèdent donc les privilèges par
-- défaut de 001_init : les droits du rôle d'exécution sont accordés ici explicitement
-- (instruction idempotente sur une base où elles sont venues après).
DO $$
DECLARE
    app text := current_setting('lotor.app_role');
BEGIN
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, mfa_totp, mfa_challenges TO %I', app);
    EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO %I', app);
    -- Suivi des migrations d'authx et de mfax : réservé au propriétaire.
    EXECUTE format('REVOKE ALL ON schema_migrations FROM %I', app);
END
$$;

-- Préférences d'un compte. default_org_id n'est qu'une préférence : la garde
-- d'organisation vérifie l'appartenance à chaque requête, et l'organisation reste soumise
-- à sa RLS (la clé étrangère ne lit rien d'autre que son existence).
CREATE TABLE account_settings (
    user_id        bigint PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    language       text CHECK (language IN ('fr', 'en')),
    theme          text CHECK (theme IN ('light', 'dark')),
    default_org_id uuid,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Méthode d'authentification de chaque session ouverte (§ 10 de l'architecture). La clé
-- est le SHA-256 du jeton de session : la table ne contient aucun jeton utilisable.
CREATE TABLE session_auth (
    session_hash bytea PRIMARY KEY CHECK (length(session_hash) = 32),
    user_id      bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    method       text NOT NULL CHECK (method IN ('local_totp', 'sso')),
    sso_org_id   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK ((method = 'sso') = (sso_org_id IS NOT NULL))
);
CREATE INDEX session_auth_user_idx ON session_auth (user_id);

-- Une session supprimée par authx (déconnexion, expiration purgée, compte supprimé) emporte
-- sa ligne : session_auth ne survit jamais à sa session.
CREATE FUNCTION lotor_session_auth_forget() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    DELETE FROM session_auth WHERE session_hash = sha256(convert_to(OLD.token, 'UTF8'));
    RETURN OLD;
END
$$;
CREATE TRIGGER session_auth_forget AFTER DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION lotor_session_auth_forget();

-- Journal d'audit des événements sans organisation : comptes, connexions, administration
-- de l'instance, démarrage (bootstrap, procédure de secours).
CREATE TABLE instance_audit_events (
    id            uuid PRIMARY KEY,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    actor_user_id bigint REFERENCES users (id) ON DELETE SET NULL,
    actor_email   text NOT NULL DEFAULT '' CHECK (length(actor_email) <= 320),
    action        text NOT NULL CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
    target_type   text NOT NULL DEFAULT '' CHECK (length(target_type) <= 64),
    target_id     text NOT NULL DEFAULT '' CHECK (length(target_id) <= 128),
    target_label  text NOT NULL DEFAULT '' CHECK (length(target_label) <= 320),
    details       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'),
    ip            text NOT NULL DEFAULT '' CHECK (length(ip) <= 64),
    request_id    text NOT NULL DEFAULT '' CHECK (length(request_id) <= 64)
);
CREATE INDEX instance_audit_events_time_idx ON instance_audit_events (occurred_at DESC, id DESC);
CREATE INDEX instance_audit_events_action_idx ON instance_audit_events (action, target_id);
