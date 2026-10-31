-- 009_vulnerabilities : catalogue des vulnérabilités et base Grype commune aux instances
-- (T06, § 8 et § 12 de l'architecture, ADR 0017).
--
-- Tables globales, sans RLS : le catalogue est public, les archives de la base aussi.
-- Aucune ne porte de donnée d'organisation.

-- Catalogue : une ligne par identifiant (CVE quand la source en cite un seul, sinon celui
-- de la source). source_rank garde la fiche la plus fiable : 0 pour le NVD, 1 sinon ; une
-- analyse ne remplace une fiche que par une fiche de rang égal ou meilleur.
CREATE TABLE vulnerabilities (
    id              text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$' AND length(id) <= 128),
    aliases         text[] NOT NULL DEFAULT '{}',
    namespace       text NOT NULL DEFAULT '' CHECK (length(namespace) <= 256),
    source_rank     smallint NOT NULL CHECK (source_rank BETWEEN 0 AND 1),
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'negligible', 'unknown')),
    cvss_score      numeric(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss            jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(cvss) = 'array'),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 16384),
    data_source     text NOT NULL DEFAULT '' CHECK (length(data_source) <= 2048),
    urls            text[] NOT NULL DEFAULT '{}',
    cwes            text[] NOT NULL DEFAULT '{}',
    epss            numeric(6, 5) CHECK (epss BETWEEN 0 AND 1),
    epss_percentile numeric(6, 5) CHECK (epss_percentile BETWEEN 0 AND 1),
    epss_date       date,
    kev             boolean NOT NULL DEFAULT false,
    kev_added       date,
    kev_due         date,
    kev_ransomware  boolean NOT NULL DEFAULT false,
    risk            numeric(5, 2) NOT NULL DEFAULT 0 CHECK (risk BETWEEN 0 AND 100),
    -- Base qui a écrit la fiche.
    vulndb_built    timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    CHECK ((epss IS NULL) = (epss_percentile IS NULL))
);
-- Recherche d'une vulnérabilité par alias (GHSA d'un CVE, T09).
CREATE INDEX vulnerabilities_aliases_idx ON vulnerabilities USING gin (aliases);

-- Archive vérifiée de la base Grype (téléchargée ou importée), découpée en blocs pour
-- qu'aucune lecture ni écriture ne tienne l'archive entière en mémoire.
CREATE TABLE vulndb_archives (
    id           uuid PRIMARY KEY,
    sha256       bytea NOT NULL UNIQUE CHECK (length(sha256) = 32),
    size         bigint NOT NULL CHECK (size > 0),
    chunk_count  integer NOT NULL CHECK (chunk_count > 0),
    schema       text NOT NULL CHECK (length(schema) BETWEEN 1 AND 32),
    built_at     timestamptz NOT NULL,
    origin       text NOT NULL CHECK (origin IN ('download', 'import')),
    source_url   text NOT NULL DEFAULT '' CHECK (length(source_url) <= 2048),
    created_at   timestamptz NOT NULL
);

CREATE TABLE vulndb_archive_chunks (
    archive_id uuid NOT NULL REFERENCES vulndb_archives (id) ON DELETE CASCADE,
    seq        integer NOT NULL CHECK (seq >= 0),
    data       bytea NOT NULL CHECK (length(data) > 0),
    PRIMARY KEY (archive_id, seq)
);
-- Déjà compressé : PostgreSQL ne tente pas de le recompresser.
ALTER TABLE vulndb_archive_chunks ALTER COLUMN data SET STORAGE EXTERNAL;

-- Version cible commune : une seule ligne. Chaque instance worker synchronise sa copie
-- locale sur target_archive_id avant d'analyser.
CREATE TABLE vulndb_state (
    singleton         boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    target_archive_id uuid REFERENCES vulndb_archives (id),
    target_set_at     timestamptz,
    last_check_at     timestamptz,
    last_check_error  text NOT NULL DEFAULT '' CHECK (length(last_check_error) <= 500),
    CHECK ((target_archive_id IS NULL) = (target_set_at IS NULL))
);
INSERT INTO vulndb_state (singleton) VALUES (true);
