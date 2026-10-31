-- 006_projects_agents : projets, références suivies, agents et leurs jetons (T04), toutes
-- tables d'organisation sous la RLS standard (§ 9 de l'architecture).
--
-- Les clés étrangères composites portent aussi la nature des lignes quand elle fait une
-- règle : un projet n'est confié qu'à un agent de même nature (dépôt ou serveur), une
-- référence « host » n'existe que sur un projet de serveur, un jeton d'inscription ne
-- désigne qu'un projet de serveur. PostgreSQL les vérifie, pas seulement le code.

CREATE TABLE agents (
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id           uuid NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('host', 'repo')),
    name         text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    version      text NOT NULL DEFAULT '' CHECK (length(version) <= 64),
    last_seen_at timestamptz,
    disabled_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   bigint REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, id, kind)
);
-- Un nom ne désigne qu'un agent actif ; un agent désactivé libère le sien (réinscription).
CREATE UNIQUE INDEX agents_active_name ON agents (org_id, lower(name)) WHERE disabled_at IS NULL;
CREATE INDEX agents_list_idx ON agents (org_id, lower(name), id);
CALL lotor_enforce_org_rls('agents');

CREATE TABLE projects (
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id          uuid NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('repo', 'host')),
    slug        text NOT NULL CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$'),
    name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    labels      jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    forge_url   text NOT NULL DEFAULT '' CHECK (length(forge_url) <= 500 AND (kind = 'repo' OR forge_url = '')),
    agent_id    uuid,
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, id, kind),
    UNIQUE (org_id, slug),
    FOREIGN KEY (org_id, agent_id, kind) REFERENCES agents (org_id, id, kind)
);
-- Un agent serveur couvre un seul hôte.
CREATE UNIQUE INDEX projects_one_host_per_agent ON projects (org_id, agent_id) WHERE kind = 'host';
CREATE INDEX projects_agent_idx ON projects (org_id, agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX projects_list_idx ON projects (org_id, lower(name), id);

CALL lotor_enforce_org_rls('projects');

-- Références suivies : branches et étiquettes d'un dépôt, ou l'unique référence d'un hôte.
-- Une référence retirée garde sa ligne (removed_at) : l'historique de ses instantanés
-- (T05) survit à un retrait, et la réajouter la réactive.
CREATE TABLE tracked_refs (
    org_id       uuid NOT NULL,
    id           uuid NOT NULL,
    project_id   uuid NOT NULL,
    project_kind text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('branch', 'tag', 'host')),
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    removed_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, project_id, kind, name),
    CHECK ((kind = 'host') = (project_kind = 'host')),
    FOREIGN KEY (org_id, project_id, project_kind) REFERENCES projects (org_id, id, kind) ON DELETE CASCADE
);
CREATE UNIQUE INDEX tracked_refs_one_per_host ON tracked_refs (org_id, project_id) WHERE kind = 'host';
-- Un hôte n'est suivi que par un projet de l'organisation.
CREATE UNIQUE INDEX tracked_refs_host_name ON tracked_refs (org_id, lower(name)) WHERE kind = 'host';
CALL lotor_enforce_org_rls('tracked_refs');

-- Jetons d'agent : seul le SHA-256 du secret est stocké ; public_id est unique sur toute
-- l'instance, car le jeton seul désigne son organisation (crossorg, migration 007).
CREATE TABLE agent_tokens (
    org_id       uuid NOT NULL,
    id           uuid NOT NULL,
    agent_id     uuid NOT NULL,
    public_id    text NOT NULL UNIQUE CHECK (public_id ~ '^[a-z2-7]{26}$'),
    secret_hash  bytea NOT NULL CHECK (length(secret_hash) = 32),
    name         text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    expires_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   bigint REFERENCES users (id) ON DELETE SET NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    revoked_by   bigint REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE
);
CREATE INDEX agent_tokens_agent_idx ON agent_tokens (org_id, agent_id, created_at DESC);
CALL lotor_enforce_org_rls('agent_tokens');

-- Jetons d'inscription des agents serveur : durée de validité, nombre d'usages, étiquettes
-- des projets créés à l'inscription, ou projet de serveur existant à rattacher.
CREATE TABLE enrollment_tokens (
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id           uuid NOT NULL,
    public_id    text NOT NULL UNIQUE CHECK (public_id ~ '^[a-z2-7]{26}$'),
    secret_hash  bytea NOT NULL CHECK (length(secret_hash) = 32),
    name         text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    expires_at   timestamptz NOT NULL,
    max_uses     integer NOT NULL CHECK (max_uses BETWEEN 1 AND 10000),
    uses         integer NOT NULL DEFAULT 0 CHECK (uses BETWEEN 0 AND max_uses),
    labels       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    project_id   uuid,
    project_kind text NOT NULL DEFAULT 'host' CHECK (project_kind = 'host'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   bigint REFERENCES users (id) ON DELETE SET NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    revoked_by   bigint REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, project_id, project_kind) REFERENCES projects (org_id, id, kind) ON DELETE CASCADE
);
CREATE INDEX enrollment_tokens_list_idx ON enrollment_tokens (org_id, created_at DESC, id DESC);
CALL lotor_enforce_org_rls('enrollment_tokens');
