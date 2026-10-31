-- 008_inventory : SBOM reçus, ingestions, composants, ensembles d'inventaire adressés par
-- contenu, instantanés et état courant des références (T05, § 8 et § 11 de
-- l'architecture). Toutes tables d'organisation sous la RLS standard (§ 9).
--
-- Clés étrangères composites : une ingestion, un instantané ou un état courant désignent
-- une référence avec son projet (tracked_refs (org_id, id, project_id)), si bien que le
-- projet ne peut pas contredire la référence ; ref_current désigne son instantané avec
-- l'ensemble de celui-ci (ON UPDATE CASCADE), si bien que l'ensemble courant est toujours
-- celui de l'instantané courant. Les références et les projets ne sont jamais supprimés
-- (retrait, archivage) : l'historique les garde.

-- Les jobs d'organisation désignent une organisation réelle (point laissé ouvert en T02
-- et T03) ; la table jobs reste globale et sans RLS.
ALTER TABLE jobs ADD CONSTRAINT jobs_org_fk FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;

ALTER TABLE tracked_refs ADD CONSTRAINT tracked_refs_with_project UNIQUE (org_id, id, project_id);

-- SBOM reçu, compressé (gzip) et dédoublonné par l'empreinte SHA-256 du JSON décompressé.
CREATE TABLE sbom_blobs (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id              uuid NOT NULL,
    sha256          bytea NOT NULL CHECK (length(sha256) = 32),
    size            bigint NOT NULL CHECK (size > 0),
    compressed_size bigint NOT NULL CHECK (compressed_size > 0),
    content         bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, sha256),
    CHECK (length(content) = compressed_size)
);
-- Déjà compressé : PostgreSQL ne tente pas de le recompresser.
ALTER TABLE sbom_blobs ALTER COLUMN content SET STORAGE EXTERNAL;
CALL ogsbom_enforce_org_rls('sbom_blobs');

-- Composant de l'organisation, identifié par son purl canonique. CPE et empreintes de
-- fichier s'accumulent au fil des SBOM (union) ; le reste est immuable.
CREATE TABLE components (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id         uuid NOT NULL,
    purl       text NOT NULL CHECK (purl LIKE 'pkg:%' AND length(purl) <= 2048),
    purl_base  text NOT NULL CHECK (purl_base LIKE 'pkg:%' AND length(purl_base) <= 2048),
    type       text NOT NULL CHECK (length(type) BETWEEN 1 AND 64),
    name       text NOT NULL CHECK (length(name) <= 512),
    version    text NOT NULL CHECK (length(version) <= 256),
    cpes       text[] NOT NULL DEFAULT '{}',
    hashes     text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, purl)
);
CREATE INDEX components_purl_base_idx ON components (org_id, purl_base);
CALL ogsbom_enforce_org_rls('components');

-- Ensemble d'inventaire adressé par son empreinte (sbom.Fingerprint) : deux instantanés au
-- même inventaire le partagent. Ses éléments sont écrits avec lui, dans la même
-- transaction, et ne changent plus.
CREATE TABLE component_sets (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id              uuid NOT NULL,
    fingerprint     bytea NOT NULL CHECK (length(fingerprint) = 32),
    component_count integer NOT NULL CHECK (component_count >= 0),
    syft_count      integer NOT NULL CHECK (syft_count >= 0),
    ia_count        integer NOT NULL CHECK (ia_count >= 0),
    weak_count      integer NOT NULL CHECK (weak_count >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, fingerprint),
    CHECK (component_count = syft_count + ia_count AND weak_count <= component_count)
);
CALL ogsbom_enforce_org_rls('component_sets');

CREATE TABLE component_set_items (
    org_id       uuid NOT NULL,
    set_id       uuid NOT NULL,
    component_id uuid NOT NULL,
    origin       text NOT NULL CHECK (origin IN ('syft', 'ia')),
    confidence   numeric(5, 4) CHECK (confidence BETWEEN 0 AND 1),
    model        text NOT NULL DEFAULT '' CHECK (length(model) <= 128),
    scope        text CHECK (scope IN ('required', 'optional', 'excluded')),
    weak_id      boolean NOT NULL DEFAULT false,
    licenses     text[] NOT NULL DEFAULT '{}',
    evidence     jsonb,
    PRIMARY KEY (org_id, set_id, component_id),
    FOREIGN KEY (org_id, set_id) REFERENCES component_sets (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, component_id) REFERENCES components (org_id, id)
);
-- Ensembles qui contiennent un composant (recherche, T09).
CREATE INDEX component_set_items_component_idx ON component_set_items (org_id, component_id);
CALL ogsbom_enforce_org_rls('component_set_items');

-- Instantané d'une référence. Dépôt : un par (référence, commit), même à inventaire
-- inchangé. Hôte : sans commit ; un envoi identique à l'inventaire courant ne fait
-- qu'avancer last_scanned_at.
CREATE TABLE snapshots (
    org_id          uuid NOT NULL,
    id              uuid NOT NULL,
    project_id      uuid NOT NULL,
    ref_id          uuid NOT NULL,
    commit_sha      text CHECK (commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    agent_id        uuid,
    agent_version   text NOT NULL DEFAULT '' CHECK (length(agent_version) <= 64),
    scanned_at      timestamptz NOT NULL,
    last_scanned_at timestamptz NOT NULL,
    blob_id         uuid NOT NULL,
    set_id          uuid NOT NULL,
    format          text NOT NULL CHECK (format IN ('cyclonedx', 'spdx', 'syft')),
    spec_version    text NOT NULL CHECK (length(spec_version) BETWEEN 1 AND 32),
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    -- Les commits NULL (hôtes) restent distincts.
    UNIQUE (org_id, ref_id, commit_sha),
    UNIQUE (org_id, id, ref_id, set_id),
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE SET NULL (agent_id),
    FOREIGN KEY (org_id, blob_id) REFERENCES sbom_blobs (org_id, id),
    FOREIGN KEY (org_id, set_id) REFERENCES component_sets (org_id, id),
    CHECK (last_scanned_at >= scanned_at)
);
CREATE INDEX snapshots_ref_idx ON snapshots (org_id, ref_id, scanned_at DESC, id DESC);
CREATE INDEX snapshots_project_idx ON snapshots (org_id, project_id, scanned_at DESC, id DESC);
CREATE INDEX snapshots_set_idx ON snapshots (org_id, set_id);
CALL ogsbom_enforce_org_rls('snapshots');

-- Instantané et ensemble courants de chaque référence : le plus récent par date de scan.
CREATE TABLE ref_current (
    org_id      uuid NOT NULL,
    ref_id      uuid NOT NULL,
    project_id  uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    set_id      uuid NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (org_id, ref_id),
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id),
    FOREIGN KEY (org_id, snapshot_id, ref_id, set_id) REFERENCES snapshots (org_id, id, ref_id, set_id) ON UPDATE CASCADE
);
CREATE INDEX ref_current_set_idx ON ref_current (org_id, set_id);
CREATE INDEX ref_current_project_idx ON ref_current (org_id, project_id);
CALL ogsbom_enforce_org_rls('ref_current');

-- Réception d'un SBOM et suivi de son décodage. Une ingestion refusée avant stockage
-- (document illisible ou trop gros à la réception) n'a pas de blob.
CREATE TABLE ingestions (
    org_id          uuid NOT NULL,
    id              uuid NOT NULL,
    agent_id        uuid NOT NULL,
    project_id      uuid NOT NULL,
    ref_id          uuid NOT NULL,
    commit_sha      text CHECK (commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    agent_version   text NOT NULL DEFAULT '' CHECK (length(agent_version) <= 64),
    scanned_at      timestamptz NOT NULL,
    blob_id         uuid,
    status          text NOT NULL CHECK (status IN ('queued', 'processing', 'done', 'failed')),
    error_key       text CHECK (error_key ~ '^error\.[a-z_]+(\.[a-z_]+)*$' AND length(error_key) <= 64),
    error_detail    text NOT NULL DEFAULT '' CHECK (length(error_detail) <= 200),
    format          text CHECK (format IN ('cyclonedx', 'spdx', 'syft')),
    spec_version    text CHECK (length(spec_version) BETWEEN 1 AND 32),
    component_count integer CHECK (component_count >= 0),
    skipped_count   integer CHECK (skipped_count >= 0),
    snapshot_id     uuid,
    outcome         text CHECK (outcome IN ('created', 'replaced', 'unchanged')),
    received_at     timestamptz NOT NULL,
    started_at      timestamptz,
    finished_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, ref_id, project_id) REFERENCES tracked_refs (org_id, id, project_id),
    FOREIGN KEY (org_id, blob_id) REFERENCES sbom_blobs (org_id, id),
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id),
    CHECK ((status = 'failed') = (error_key IS NOT NULL)),
    CHECK ((status = 'done') = (snapshot_id IS NOT NULL AND outcome IS NOT NULL)),
    CHECK ((status IN ('done', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (status = 'failed' OR blob_id IS NOT NULL)
);
CREATE INDEX ingestions_project_idx ON ingestions (org_id, project_id, received_at DESC, id DESC);
-- Envoi en double d'un dépôt (même référence, même commit, même SBOM).
CREATE INDEX ingestions_duplicate_idx ON ingestions (org_id, ref_id, commit_sha, blob_id) WHERE status <> 'failed';
CREATE INDEX ingestions_snapshot_idx ON ingestions (org_id, snapshot_id) WHERE snapshot_id IS NOT NULL;
CALL ogsbom_enforce_org_rls('ingestions');
