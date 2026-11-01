-- 017_snapshot_history : différences entre ensembles d'inventaire et rétention des
-- instantanés (T17, ADR 0038 et 0039). Tables d'organisation sous la RLS standard (§ 9).

-- Différence entre deux ensembles d'inventaire, calculée pour chaque couple d'instantanés
-- consécutifs d'une référence (job inventory.diff) : elle vaut pour tout couple
-- d'instantanés aux mêmes ensembles, de n'importe quelle référence. Elle disparaît avec
-- l'un de ses ensembles (rétention).
CREATE TABLE set_diffs (
    org_id           uuid NOT NULL,
    from_set_id      uuid NOT NULL,
    to_set_id        uuid NOT NULL,
    added_count      integer NOT NULL CHECK (added_count >= 0),
    removed_count    integer NOT NULL CHECK (removed_count >= 0),
    upgraded_count   integer NOT NULL CHECK (upgraded_count >= 0),
    downgraded_count integer NOT NULL CHECK (downgraded_count >= 0),
    computed_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, from_set_id, to_set_id),
    FOREIGN KEY (org_id, from_set_id) REFERENCES component_sets (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, to_set_id) REFERENCES component_sets (org_id, id) ON DELETE CASCADE,
    CHECK (from_set_id <> to_set_id)
);
-- Suppression d'un ensemble (clé étrangère côté « vers »).
CREATE INDEX set_diffs_to_idx ON set_diffs (org_id, to_set_id);
CALL lotor_enforce_org_rls('set_diffs');

-- Changements d'une différence : un ajout n'a qu'un nouveau composant, un retrait qu'un
-- ancien ; une montée ou une descente relie deux versions d'un même purl_base.
-- approximate : versions incomparables dans leur écosystème, sens déduit de l'ordre des
-- chaînes.
CREATE TABLE set_diff_items (
    org_id           uuid NOT NULL,
    from_set_id      uuid NOT NULL,
    to_set_id        uuid NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('added', 'removed', 'upgraded', 'downgraded')),
    purl_base        text NOT NULL CHECK (purl_base LIKE 'pkg:%' AND length(purl_base) <= 2048),
    old_component_id uuid,
    new_component_id uuid,
    approximate      boolean NOT NULL DEFAULT false,
    UNIQUE NULLS NOT DISTINCT (org_id, from_set_id, to_set_id, old_component_id, new_component_id),
    FOREIGN KEY (org_id, from_set_id, to_set_id) REFERENCES set_diffs (org_id, from_set_id, to_set_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, old_component_id) REFERENCES components (org_id, id),
    FOREIGN KEY (org_id, new_component_id) REFERENCES components (org_id, id),
    CHECK (CASE kind
             WHEN 'added' THEN old_component_id IS NULL AND new_component_id IS NOT NULL
             WHEN 'removed' THEN old_component_id IS NOT NULL AND new_component_id IS NULL
             ELSE old_component_id IS NOT NULL AND new_component_id IS NOT NULL
           END)
);
-- Lecture d'une différence par nature puis par paquet (pagination de l'écran et de l'API).
CREATE INDEX set_diff_items_read_idx ON set_diff_items (org_id, from_set_id, to_set_id, kind, purl_base);
CALL lotor_enforce_org_rls('set_diff_items');

-- Dernier passage de la rétention d'une organisation. horizon est la plus récente date de
-- coupure appliquée : avant elle, l'historique d'une référence est réduit (un instantané
-- par mois) ; la recherche à une date passée (T21) avertit en deçà.
CREATE TABLE snapshot_retention (
    org_id              uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    horizon             timestamptz NOT NULL,
    last_run_at         timestamptz NOT NULL,
    snapshots_deleted   bigint NOT NULL CHECK (snapshots_deleted >= 0),
    ingestions_deleted  bigint NOT NULL CHECK (ingestions_deleted >= 0),
    sets_deleted        bigint NOT NULL CHECK (sets_deleted >= 0),
    blobs_deleted       bigint NOT NULL CHECK (blobs_deleted >= 0),
    PRIMARY KEY (org_id)
);
CALL lotor_enforce_org_rls('snapshot_retention');

-- Un constat et son historique gardent leur instantané tant qu'il existe : la rétention
-- peut supprimer le dernier instantané qui a vu un constat résolu depuis longtemps. Le
-- constat reste, sans instantané.
ALTER TABLE findings ALTER COLUMN snapshot_id DROP NOT NULL;
ALTER TABLE findings DROP CONSTRAINT findings_org_id_snapshot_id_fkey;
ALTER TABLE findings ADD CONSTRAINT findings_org_id_snapshot_id_fkey
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id) ON DELETE SET NULL (snapshot_id);
ALTER TABLE finding_events ALTER COLUMN snapshot_id DROP NOT NULL;
ALTER TABLE finding_events DROP CONSTRAINT finding_events_org_id_snapshot_id_fkey;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_org_id_snapshot_id_fkey
    FOREIGN KEY (org_id, snapshot_id) REFERENCES snapshots (org_id, id) ON DELETE SET NULL (snapshot_id);

-- Index des contrôles de clés étrangères et des recherches d'orphelins de la rétention :
-- sans eux, chaque instantané, ensemble ou SBOM supprimé parcourrait toute la table qui le
-- référence.
CREATE INDEX findings_snapshot_idx ON findings (org_id, snapshot_id);
CREATE INDEX finding_events_snapshot_idx ON finding_events (org_id, snapshot_id);
CREATE INDEX ref_current_snapshot_idx ON ref_current (org_id, snapshot_id);
CREATE INDEX ref_analyses_snapshot_idx ON ref_analyses (org_id, snapshot_id);
CREATE INDEX ref_analyses_set_idx ON ref_analyses (org_id, set_id);
CREATE INDEX snapshots_blob_idx ON snapshots (org_id, blob_id);
CREATE INDEX ingestions_blob_idx ON ingestions (org_id, blob_id) WHERE blob_id IS NOT NULL;
-- Purge des réceptions terminées hors de la fenêtre de rétention.
CREATE INDEX ingestions_received_idx ON ingestions (org_id, received_at) WHERE status IN ('done', 'failed');
