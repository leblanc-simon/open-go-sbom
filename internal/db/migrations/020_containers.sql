-- 020_containers : conteneurs en projets enfants de leur hôte (T13, ADR 0040).
--
-- Un conteneur qui tourne sur un hôte suivi devient un projet de nature « container »,
-- enfant du projet de l'hôte (parent_id). Son identité dans l'hôte (container_key) est
-- « projet/service » pour un service Compose (ses répliques forment un seul projet), le
-- nom du conteneur sinon ; elle est aussi le nom de son unique référence suivie. Le
-- projet enfant est toujours dans l'équipe de son hôte : la clé étrangère composite qui
-- porte l'équipe le garantit, et ON UPDATE CASCADE fait suivre les enfants quand l'hôte
-- change d'équipe. Un enfant n'a pas d'agent propre : c'est l'agent de son hôte qui
-- l'inventorie. seen_at est le dernier signalement du conteneur par l'agent ;
-- archived_absent distingue un archivage pour absence (levé quand le conteneur
-- réapparaît) d'un archivage voulu par un utilisateur (qui tient).

ALTER TABLE projects DROP CONSTRAINT projects_kind_check;
ALTER TABLE projects ADD CONSTRAINT projects_kind_check CHECK (kind IN ('repo', 'host', 'container'));

-- Cible de la clé étrangère des enfants : (projet, nature, équipe) d'un hôte.
ALTER TABLE projects ADD CONSTRAINT projects_team_key UNIQUE (org_id, id, kind, team_id);

ALTER TABLE projects
    ADD COLUMN parent_id       uuid,
    ADD COLUMN parent_kind     text CHECK (parent_kind = 'host'),
    ADD COLUMN container_key   text CHECK (length(container_key) BETWEEN 1 AND 255),
    ADD COLUMN container       jsonb CHECK (jsonb_typeof(container) = 'object' AND pg_column_size(container) <= 8192),
    ADD COLUMN seen_at         timestamptz,
    ADD COLUMN archived_absent boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT projects_parent_fk FOREIGN KEY (org_id, parent_id, parent_kind, team_id)
        REFERENCES projects (org_id, id, kind, team_id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD CONSTRAINT projects_container_shape CHECK (
        (kind = 'container') = (parent_id IS NOT NULL)
        AND (kind = 'container') = (parent_kind IS NOT NULL)
        AND (kind = 'container') = (container_key IS NOT NULL)
        AND (kind = 'container') = (seen_at IS NOT NULL)
        AND (kind = 'container' OR (container IS NULL AND NOT archived_absent))
        AND (kind <> 'container' OR agent_id IS NULL)
        AND (archived_at IS NOT NULL OR NOT archived_absent));

-- Une identité désigne un seul enfant par hôte, archivé ou non : un conteneur qui
-- réapparaît retrouve son projet et son historique.
CREATE UNIQUE INDEX projects_container_key ON projects (org_id, parent_id, container_key) WHERE kind = 'container';
-- Enfants actifs absents depuis longtemps (archivage), et enfants d'un hôte.
CREATE INDEX projects_container_seen ON projects (org_id, seen_at) WHERE kind = 'container' AND archived_at IS NULL;
CREATE INDEX projects_parent_idx ON projects (org_id, parent_id) WHERE parent_id IS NOT NULL;

-- Références : un conteneur suit une seule référence, de nature « container ».
ALTER TABLE tracked_refs DROP CONSTRAINT tracked_refs_kind_check;
ALTER TABLE tracked_refs ADD CONSTRAINT tracked_refs_kind_check CHECK (kind IN ('branch', 'tag', 'host', 'container'));
ALTER TABLE tracked_refs DROP CONSTRAINT tracked_refs_check;
ALTER TABLE tracked_refs ADD CONSTRAINT tracked_refs_kind_matches_project CHECK (
    (kind = 'host') = (project_kind = 'host') AND (kind = 'container') = (project_kind = 'container'));
CREATE UNIQUE INDEX tracked_refs_one_per_container ON tracked_refs (org_id, project_id) WHERE kind = 'container';
