-- 012_dashboard : statistiques quotidiennes du tableau de bord (T10, § 8 de
-- l'architecture, ADR 0027). Tables d'organisation sous la RLS standard (§ 9).
--
-- Une ligne par jour (UTC) : l'état observé à la dernière exécution du job ce jour-là,
-- donc l'état de fin de journée une fois le jour écoulé. Les indicateurs « instantanés »
-- de l'écran se calculent sur les tables courantes ; seules les séries temporelles lisent
-- ces tables. Constats ouverts comptés sur les références actives des projets actifs.

CREATE TABLE org_daily_stats (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    day             date NOT NULL,
    open_critical   integer NOT NULL CHECK (open_critical >= 0),
    open_high       integer NOT NULL CHECK (open_high >= 0),
    open_medium     integer NOT NULL CHECK (open_medium >= 0),
    open_low        integer NOT NULL CHECK (open_low >= 0),
    open_negligible integer NOT NULL CHECK (open_negligible >= 0),
    open_unknown    integer NOT NULL CHECK (open_unknown >= 0),
    -- Constats ouverts marqués KEV, et vulnérabilités KEV distinctes qu'ils portent.
    open_kev        integer NOT NULL CHECK (open_kev >= 0),
    kev_vulns       integer NOT NULL CHECK (kev_vulns >= 0),
    projects        integer NOT NULL CHECK (projects >= 0),
    silent_agents   integer NOT NULL CHECK (silent_agents >= 0),
    -- Constats résolus ce jour-là et délai médian de correction (resolved_at −
    -- first_seen_at, en secondes ; NULL sans constat résolu), par sévérité.
    fixed_critical    integer NOT NULL CHECK (fixed_critical >= 0),
    fixed_high        integer NOT NULL CHECK (fixed_high >= 0),
    fixed_medium      integer NOT NULL CHECK (fixed_medium >= 0),
    fixed_low         integer NOT NULL CHECK (fixed_low >= 0),
    fixed_negligible  integer NOT NULL CHECK (fixed_negligible >= 0),
    fixed_unknown     integer NOT NULL CHECK (fixed_unknown >= 0),
    fix_p50_critical   double precision CHECK (fix_p50_critical >= 0),
    fix_p50_high       double precision CHECK (fix_p50_high >= 0),
    fix_p50_medium     double precision CHECK (fix_p50_medium >= 0),
    fix_p50_low        double precision CHECK (fix_p50_low >= 0),
    fix_p50_negligible double precision CHECK (fix_p50_negligible >= 0),
    fix_p50_unknown    double precision CHECK (fix_p50_unknown >= 0),
    recorded_at     timestamptz NOT NULL,
    PRIMARY KEY (org_id, day)
);
CALL ogsbom_enforce_org_rls('org_daily_stats');

-- Même série à l'échelle d'un projet actif (en-tête de la fiche projet).
CREATE TABLE project_daily_stats (
    org_id          uuid NOT NULL,
    project_id      uuid NOT NULL,
    day             date NOT NULL,
    open_critical   integer NOT NULL CHECK (open_critical >= 0),
    open_high       integer NOT NULL CHECK (open_high >= 0),
    open_medium     integer NOT NULL CHECK (open_medium >= 0),
    open_low        integer NOT NULL CHECK (open_low >= 0),
    open_negligible integer NOT NULL CHECK (open_negligible >= 0),
    open_unknown    integer NOT NULL CHECK (open_unknown >= 0),
    open_kev        integer NOT NULL CHECK (open_kev >= 0),
    recorded_at     timestamptz NOT NULL,
    PRIMARY KEY (org_id, project_id, day),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id) ON DELETE CASCADE
);
CALL ogsbom_enforce_org_rls('project_daily_stats');

-- Délai de correction sur une période : constats résolus par date de résolution.
CREATE INDEX findings_resolved_idx ON findings (org_id, resolved_at) WHERE status = 'resolved';
