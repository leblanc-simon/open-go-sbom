-- 021_policies : politiques, violations, canaux de notification et envois (T15,
-- ADR 0045 et 0046). Tables d'organisation sous la RLS standard (§ 9).
--
-- Une politique est une règle CEL évaluée sur un sujet : un constat ouvert (avec son
-- projet, son composant et son statut de triage) ou un agent. Une violation est un couple
-- (politique, sujet) qui satisfait la règle, de son ouverture à sa résolution ; une
-- nouvelle violation du même couple n'est ouverte qu'après la résolution de la
-- précédente : c'est ce qui dédoublonne les notifications.

CREATE TABLE notification_channels (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id              uuid NOT NULL,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    kind            text NOT NULL CHECK (kind IN ('email', 'webhook', 'matrix', 'mattermost', 'slack')),
    -- Réglages sans secret : destinataires d'un e-mail, URL d'un webhook générique,
    -- serveur et salon Matrix.
    settings        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(settings) = 'object'),
    -- Secret du canal (clé HMAC, URL d'un webhook entrant Slack ou Mattermost, jeton
    -- Matrix), chiffré par internal/secret avec la ligne en données associées.
    secret          bytea,
    secret_key_id   text CHECK (length(secret_key_id) BETWEEN 1 AND 64),
    enabled         boolean NOT NULL DEFAULT true,
    -- Dernier envoi réussi et dernier échec (clé d'erreur traduisible, jamais de secret).
    last_success_at timestamptz,
    last_failure_at timestamptz,
    last_error_key  text CHECK (length(last_error_key) <= 200),
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK ((secret IS NULL) = (secret_key_id IS NULL))
);
CREATE UNIQUE INDEX notification_channels_name ON notification_channels (org_id, lower(name));
CALL lotor_enforce_org_rls('notification_channels');

CREATE TABLE policies (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id              uuid NOT NULL,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    -- Sujet évalué : un constat ouvert ou un agent.
    subject         text NOT NULL CHECK (subject IN ('finding', 'agent')),
    expression      text NOT NULL CHECK (length(expression) BETWEEN 1 AND 4000),
    -- Modèle fourni dont la règle est partie (informatif).
    template        text CHECK (length(template) <= 64),
    enabled         boolean NOT NULL DEFAULT true,
    -- Une violation bloquante rend non conforme le verdict d'un instantané.
    blocking        boolean NOT NULL DEFAULT false,
    -- Envoi des violations : immédiat, résumé quotidien, ou aucun.
    delivery        text NOT NULL CHECK (delivery IN ('immediate', 'digest', 'none')),
    -- Dernière erreur d'évaluation (règle valide qui échoue sur une donnée).
    last_error      text CHECK (length(last_error) <= 500),
    last_error_at   timestamptz,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX policies_name ON policies (org_id, lower(name));
CALL lotor_enforce_org_rls('policies');

CREATE TABLE policy_channels (
    org_id     uuid NOT NULL,
    policy_id  uuid NOT NULL,
    channel_id uuid NOT NULL,
    PRIMARY KEY (org_id, policy_id, channel_id),
    FOREIGN KEY (org_id, policy_id) REFERENCES policies (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, channel_id) REFERENCES notification_channels (org_id, id) ON DELETE CASCADE
);
CREATE INDEX policy_channels_channel_idx ON policy_channels (org_id, channel_id);
CALL lotor_enforce_org_rls('policy_channels');

CREATE TABLE policy_violations (
    org_id      uuid NOT NULL,
    id          uuid NOT NULL,
    policy_id   uuid NOT NULL,
    subject     text NOT NULL CHECK (subject IN ('finding', 'agent')),
    finding_id  uuid,
    agent_id    uuid,
    -- Projet et référence du constat (filtre d'équipe, verdict d'un instantané).
    project_id  uuid,
    ref_id      uuid,
    opened_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    resolved_at timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, policy_id) REFERENCES policies (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, finding_id) REFERENCES findings (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id) ON DELETE CASCADE,
    CHECK ((subject = 'finding') = (finding_id IS NOT NULL AND project_id IS NOT NULL AND ref_id IS NOT NULL)),
    CHECK ((subject = 'agent') = (agent_id IS NOT NULL)),
    CHECK (subject = 'finding' OR (project_id IS NULL AND ref_id IS NULL)),
    CHECK (last_seen_at >= opened_at),
    CHECK (resolved_at IS NULL OR resolved_at >= opened_at)
);
-- Une seule violation ouverte par couple (politique, sujet).
CREATE UNIQUE INDEX policy_violations_open_finding ON policy_violations (org_id, policy_id, finding_id)
    WHERE resolved_at IS NULL AND finding_id IS NOT NULL;
CREATE UNIQUE INDEX policy_violations_open_agent ON policy_violations (org_id, policy_id, agent_id)
    WHERE resolved_at IS NULL AND agent_id IS NOT NULL;
-- Violations ouvertes d'un projet (évaluation) et d'une référence (verdict).
CREATE INDEX policy_violations_project_idx ON policy_violations (org_id, project_id) WHERE resolved_at IS NULL;
CREATE INDEX policy_violations_ref_idx ON policy_violations (org_id, ref_id) WHERE resolved_at IS NULL;
-- Écran des violations, des plus récentes aux plus anciennes.
CREATE INDEX policy_violations_list_idx ON policy_violations (org_id, opened_at DESC, id DESC);
CREATE INDEX policy_violations_finding_idx ON policy_violations (org_id, finding_id) WHERE finding_id IS NOT NULL;
CREATE INDEX policy_violations_agent_idx ON policy_violations (org_id, agent_id) WHERE agent_id IS NOT NULL;
CALL lotor_enforce_org_rls('policy_violations');

-- Dernière évaluation des politiques de chaque référence : la date de l'analyse qu'elle a
-- prise en compte dit au verdict d'un instantané s'il est encore en attente.
CREATE TABLE policy_evaluations (
    org_id       uuid NOT NULL,
    ref_id       uuid NOT NULL,
    project_id   uuid NOT NULL,
    analyzed_at  timestamptz NOT NULL,
    evaluated_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, ref_id),
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id) ON DELETE CASCADE
);
CALL lotor_enforce_org_rls('policy_evaluations');

-- Envoi d'une violation sur un canal : une ligne par couple, jamais deux, d'où l'absence
-- de doublon même si l'évaluation repasse. Un envoi immédiat part par le job notify.send
-- du canal ; un envoi de résumé attend le résumé quotidien.
CREATE TABLE notification_deliveries (
    org_id       uuid NOT NULL,
    channel_id   uuid NOT NULL,
    violation_id uuid NOT NULL,
    mode         text NOT NULL CHECK (mode IN ('immediate', 'digest')),
    -- pending : à envoyer ; sent : envoyé ; skipped : violation résolue avant l'envoi.
    state        text NOT NULL CHECK (state IN ('pending', 'sent', 'skipped')),
    created_at   timestamptz NOT NULL,
    done_at      timestamptz,
    PRIMARY KEY (org_id, channel_id, violation_id),
    FOREIGN KEY (org_id, channel_id) REFERENCES notification_channels (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, violation_id) REFERENCES policy_violations (org_id, id) ON DELETE CASCADE,
    CHECK ((state = 'pending') = (done_at IS NULL))
);
CREATE INDEX notification_deliveries_pending_idx ON notification_deliveries (org_id, channel_id, mode, created_at)
    WHERE state = 'pending';
CREATE INDEX notification_deliveries_violation_idx ON notification_deliveries (org_id, violation_id);
CALL lotor_enforce_org_rls('notification_deliveries');

-- Date à laquelle un correctif a été vu pour la première fois sur un constat (règle
-- « critique avec correctif disponible depuis plus de 30 jours ») : posée par l'analyse
-- quand fix_state passe à fixed, effacée s'il n'y a plus de correctif (sans date, un
-- correctif compte pour zéro jour). Les constats
-- existants partent de leur première détection, borne la plus proche connue.
ALTER TABLE findings ADD COLUMN fixed_seen_at timestamptz,
    ADD CHECK (fix_state = 'fixed' OR fixed_seen_at IS NULL);
UPDATE findings SET fixed_seen_at = first_seen_at WHERE fix_state = 'fixed';
