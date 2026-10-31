-- 010_findings : constats (référence suivie × composant × vulnérabilité), leur historique
-- et l'état d'analyse de chaque référence (T06, § 8 et § 12 de l'architecture, ADR 0018).
-- Tables d'organisation sous la RLS standard (§ 9) ; vulnerabilities est le catalogue
-- global.

-- Constat. Un couple résolu qui réapparaît est rouvert (même ligne) ; finding_events
-- garde l'historique. Sévérité, scores et risque sont ceux de la dernière analyse, copiés
-- ici pour filtrer et trier sans jointure sur le catalogue.
CREATE TABLE findings (
    org_id          uuid NOT NULL,
    id              uuid NOT NULL,
    project_id      uuid NOT NULL,
    ref_id          uuid NOT NULL,
    component_id    uuid NOT NULL,
    vuln_id         text NOT NULL REFERENCES vulnerabilities (id),
    status          text NOT NULL CHECK (status IN ('open', 'resolved')),
    resolution      text CHECK (resolution IN ('component_removed', 'not_matched')),
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'negligible', 'unknown')),
    cvss_score      numeric(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
    epss            numeric(6, 5) CHECK (epss BETWEEN 0 AND 1),
    epss_percentile numeric(6, 5) CHECK (epss_percentile BETWEEN 0 AND 1),
    kev             boolean NOT NULL DEFAULT false,
    risk            numeric(5, 2) NOT NULL CHECK (risk BETWEEN 0 AND 100),
    fixed_versions  text[] NOT NULL DEFAULT '{}',
    fix_state       text NOT NULL CHECK (fix_state IN ('fixed', 'not-fixed', 'wont-fix', 'unknown')),
    match_type      text NOT NULL CHECK (match_type IN ('exact-direct', 'exact-indirect', 'cpe')),
    first_seen_at   timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    resolved_at     timestamptz,
    -- Dernier instantané et dernière base qui l'ont constaté.
    snapshot_id     uuid NOT NULL,
    vulndb_archive  uuid NOT NULL,
    vulndb_built    timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, ref_id, component_id, vuln_id),
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id),
    FOREIGN KEY (org_id, component_id) REFERENCES components (org_id, id),
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL AND resolution IS NOT NULL)),
    CHECK (last_seen_at >= first_seen_at)
);
-- Onglet « Constats » d'un projet et d'une référence, par risque décroissant.
CREATE INDEX findings_project_idx ON findings (org_id, project_id, status, risk DESC, id);
CREATE INDEX findings_ref_idx ON findings (org_id, ref_id, status, risk DESC, id);
-- Fiche vulnérabilité (projets touchés) et fiche composant.
CREATE INDEX findings_vuln_idx ON findings (org_id, vuln_id, status);
CREATE INDEX findings_component_idx ON findings (org_id, component_id, status);
CALL lotor_enforce_org_rls('findings');

CREATE TABLE finding_events (
    org_id         uuid NOT NULL,
    finding_id     uuid NOT NULL,
    seq            bigint GENERATED ALWAYS AS IDENTITY,
    at             timestamptz NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('opened', 'resolved', 'reopened')),
    resolution     text CHECK (resolution IN ('component_removed', 'not_matched')),
    snapshot_id    uuid NOT NULL,
    vulndb_archive uuid NOT NULL,
    PRIMARY KEY (org_id, finding_id, seq),
    FOREIGN KEY (org_id, finding_id) REFERENCES findings (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id),
    CHECK ((kind = 'resolved') = (resolution IS NOT NULL))
);
CALL lotor_enforce_org_rls('finding_events');

-- Dernière analyse de chaque référence : ensemble et base analysés. Une analyse qui
-- trouve le même couple (ensemble, base) n'a rien à faire (réanalyse idempotente).
CREATE TABLE ref_analyses (
    org_id          uuid NOT NULL,
    ref_id          uuid NOT NULL,
    project_id      uuid NOT NULL,
    set_id          uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    vulndb_archive  uuid NOT NULL,
    vulndb_built    timestamptz NOT NULL,
    analyzed_at     timestamptz NOT NULL,
    match_count     integer NOT NULL CHECK (match_count >= 0),
    -- Correspondances sur un paquet du SBOM absent de l'inventaire (composant écarté à
    -- l'ingestion, composant décrit par le document).
    unmatched_count integer NOT NULL CHECK (unmatched_count >= 0),
    PRIMARY KEY (org_id, ref_id),
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id),
    FOREIGN KEY (org_id, set_id) REFERENCES component_sets (org_id, id),
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id)
);
CALL lotor_enforce_org_rls('ref_analyses');
