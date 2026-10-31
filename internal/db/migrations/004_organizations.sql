-- 004_organizations : organisations, appartenances et journal d'audit d'organisation,
-- toutes sous la RLS standard (§ 9 de l'architecture).

CREATE TABLE organizations (
    id               uuid PRIMARY KEY,
    slug             text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$'),
    name             text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    default_language text NOT NULL CHECK (default_language IN ('fr', 'en')),
    archived_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CALL lotor_enforce_org_rls('organizations', 'id');

ALTER TABLE account_settings
    ADD CONSTRAINT account_settings_default_org_fk
    FOREIGN KEY (default_org_id) REFERENCES organizations (id) ON DELETE SET NULL;

CREATE TABLE org_memberships (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX org_memberships_user_idx ON org_memberships (user_id);
CALL lotor_enforce_org_rls('org_memberships');

CREATE TABLE audit_events (
    org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id            uuid NOT NULL,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    actor_user_id bigint REFERENCES users (id) ON DELETE SET NULL,
    actor_email   text NOT NULL DEFAULT '' CHECK (length(actor_email) <= 320),
    action        text NOT NULL CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
    target_type   text NOT NULL DEFAULT '' CHECK (length(target_type) <= 64),
    target_id     text NOT NULL DEFAULT '' CHECK (length(target_id) <= 128),
    target_label  text NOT NULL DEFAULT '' CHECK (length(target_label) <= 320),
    details       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'),
    ip            text NOT NULL DEFAULT '' CHECK (length(ip) <= 64),
    request_id    text NOT NULL DEFAULT '' CHECK (length(request_id) <= 64),
    PRIMARY KEY (org_id, id)
);
CREATE INDEX audit_events_time_idx ON audit_events (org_id, occurred_at DESC, id DESC);
CALL lotor_enforce_org_rls('audit_events');
