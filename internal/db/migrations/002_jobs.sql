-- 002_jobs : file de traitements et échéances du planificateur (internal/jobs, § 16).
--
-- Tables globales, sans RLS : elles ne portent que des références (identifiants,
-- types), jamais de donnée d'organisation. org_id est facultatif (jobs d'instance) ; un
-- handler qui touche des données d'organisation travaille dans db.InOrg(job.OrgID).
-- Toutes les dates sont fournies par l'horloge du serveur (injectable dans les tests).

CREATE TABLE jobs (
    id           uuid        PRIMARY KEY,
    kind         text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND length(kind) <= 64),
    org_id       uuid,
    payload      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    priority     smallint    NOT NULL DEFAULT 0 CHECK (priority BETWEEN -1000 AND 1000),
    status       text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'dead')),
    attempts     integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer     NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    run_at       timestamptz NOT NULL,
    -- Bail : posé à la prise, renouvelé tant que le handler tourne. lease_token désigne
    -- la prise en cours ; une fin de job qui ne le porte plus (bail perdu, repris
    -- ailleurs) est ignorée.
    locked_until timestamptz,
    lease_token  uuid,
    worker       text,
    unique_key   text        CHECK (length(unique_key) BETWEEN 1 AND 200),
    last_error   text,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    finished_at  timestamptz,
    CHECK ((status = 'running') = (lease_token IS NOT NULL AND locked_until IS NOT NULL)),
    CHECK ((status IN ('done', 'dead')) = (finished_at IS NOT NULL))
);

-- Prise : jobs en attente par priorité décroissante puis échéance.
CREATE INDEX jobs_pending ON jobs (priority DESC, run_at, id) WHERE status = 'pending';
-- Plafond par organisation, baux expirés.
CREATE INDEX jobs_running ON jobs (kind, org_id, locked_until) WHERE status = 'running';
-- Une seule mise en file en attente par (type, clé) : une seconde mise en file relève la
-- priorité et avance l'échéance (ON CONFLICT … DO UPDATE). Un job en cours n'y figure
-- pas : une nouvelle mise en file pendant son exécution crée un nouveau job, qui verra
-- la donnée la plus récente.
CREATE UNIQUE INDEX jobs_unique_pending ON jobs (kind, unique_key)
    WHERE status = 'pending' AND unique_key IS NOT NULL;
-- Nettoyage des jobs terminés, liste des jobs morts.
CREATE INDEX jobs_done ON jobs (finished_at) WHERE status = 'done';
CREATE INDEX jobs_dead ON jobs (finished_at DESC, id DESC) WHERE status = 'dead';

-- Échéances : chaque instance tente de prendre une échéance échue par
-- UPDATE … WHERE next_run_at <= maintenant ; une seule y parvient et met le job en file,
-- dans la même transaction. Ni verrou de session ni verrou consultatif.
CREATE TABLE schedules (
    name        text        PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND length(name) <= 64),
    period      interval    NOT NULL CHECK (period > interval '0'),
    -- Décalage de la grille : période 24 h et décalage 3 h → chaque jour à 03:00 UTC.
    phase       interval    NOT NULL DEFAULT interval '0' CHECK (phase >= interval '0' AND phase < period),
    next_run_at timestamptz NOT NULL,
    last_run_at timestamptz,
    updated_at  timestamptz NOT NULL
);
