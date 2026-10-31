-- 014_vulndb_admin : administration de la base de vulnérabilités (T11, § 12 de
-- l'architecture, ADR 0028) : version chargée par chaque instance worker et import
-- manuel d'une archive.
--
-- Tables globales, sans RLS : elles ne portent que des données de l'instance (archives
-- publiques, noms d'instances), jamais de donnée d'organisation.

-- Version de la base chargée par chaque instance worker, rapportée à chaque
-- synchronisation (vulndb.sync_interval). L'instance supprime sa ligne à l'arrêt ; une
-- ligne restée sans nouvelles (instance tuée) est supprimée après sept jours. archive_id
-- n'a pas de clé étrangère : la purge des archives ne doit pas effacer ce qu'une instance
-- en retard a encore chargé.
CREATE TABLE vulndb_instances (
    instance   text PRIMARY KEY CHECK (length(instance) BETWEEN 1 AND 200),
    archive_id uuid,
    built_at   timestamptz,
    schema     text CHECK (length(schema) BETWEEN 1 AND 32),
    loaded_at  timestamptz,
    sync_error text NOT NULL DEFAULT '' CHECK (length(sync_error) <= 500),
    seen_at    timestamptz NOT NULL,
    CHECK ((archive_id IS NULL) = (built_at IS NULL)
       AND (archive_id IS NULL) = (schema IS NULL)
       AND (archive_id IS NULL) = (loaded_at IS NULL))
);

-- Import manuel : l'archive téléversée est rangée par blocs (aucune transaction ne
-- traverse le téléversement : un bloc par transaction), puis un job vulndb.import la
-- vérifie et l'installe sur une instance worker, qui peut être une autre machine que
-- celle qui a reçu le fichier. Les blocs sont supprimés dès que l'import se termine.
--   uploading : téléversement en cours ;
--   queued    : téléversement complet, job en file ;
--   done      : archive importée (archive_id) ;
--   failed    : refusée ou abandonnée (error).
CREATE TABLE vulndb_imports (
    id              uuid PRIMARY KEY,
    status          text NOT NULL CHECK (status IN ('uploading', 'queued', 'done', 'failed')),
    size            bigint NOT NULL DEFAULT 0 CHECK (size >= 0),
    chunk_count     integer NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
    sha256          bytea CHECK (length(sha256) = 32),
    file_name       text NOT NULL DEFAULT '' CHECK (length(file_name) <= 255),
    requested_by    text NOT NULL DEFAULT '' CHECK (length(requested_by) <= 320),
    archive_id      uuid,
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 500),
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    finished_at     timestamptz,
    CHECK ((status IN ('done', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (status IN ('uploading', 'failed') OR sha256 IS NOT NULL),
    CHECK ((status = 'done') = (archive_id IS NOT NULL))
);
-- Un seul import en cours à la fois : chacun peut peser plusieurs centaines de Mio.
CREATE UNIQUE INDEX vulndb_imports_active ON vulndb_imports ((true)) WHERE status IN ('uploading', 'queued');
CREATE INDEX vulndb_imports_recent ON vulndb_imports (created_at DESC, id DESC);

CREATE TABLE vulndb_import_chunks (
    import_id uuid NOT NULL REFERENCES vulndb_imports (id) ON DELETE CASCADE,
    seq       integer NOT NULL CHECK (seq >= 0),
    data      bytea NOT NULL CHECK (length(data) > 0),
    PRIMARY KEY (import_id, seq)
);
-- Déjà compressé : PostgreSQL ne tente pas de le recompresser.
ALTER TABLE vulndb_import_chunks ALTER COLUMN data SET STORAGE EXTERNAL;
