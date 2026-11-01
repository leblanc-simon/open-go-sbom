-- 016_teams : équipes, rôles d'équipe et invitations (T16, ADR 0034).
--
-- Le rôle d'organisation se réduit à « member » ou « admin » ; les droits sur un projet
-- viennent du rôle dans son équipe (reader, analyst, admin). L'existant passe dans une
-- équipe « Général » par organisation (« General » pour une organisation en anglais) :
-- tous les projets y sont rattachés, tous les membres en deviennent membres avec leur
-- rôle d'organisation actuel (viewer → reader, analyst → analyst, admin → admin), puis
-- viewer et analyst deviennent « member ». Les identifiants créés ici sont des UUID v4
-- (gen_random_uuid) : l'application tire des UUID v7, mais rien ne dépend de leur ordre.

CREATE TABLE teams (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id         uuid NOT NULL,
    name       text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by bigint REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX teams_name ON teams (org_id, lower(name));
CALL lotor_enforce_org_rls('teams');

-- Un membre d'équipe est forcément membre de l'organisation : la clé étrangère composite
-- vers org_memberships le garantit, et le retrait de l'organisation le retire de ses
-- équipes.
CREATE TABLE team_members (
    org_id     uuid NOT NULL,
    team_id    uuid NOT NULL,
    user_id    bigint NOT NULL,
    role       text NOT NULL CHECK (role IN ('reader', 'analyst', 'admin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, team_id, user_id),
    FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, user_id) REFERENCES org_memberships (org_id, user_id) ON DELETE CASCADE
);
CREATE INDEX team_members_user_idx ON team_members (org_id, user_id);
CALL lotor_enforce_org_rls('team_members');

-- Invitations (SEC-09) : un compte ne devient membre qu'en acceptant. L'e-mail est stocké
-- normalisé, sans référence à users : l'invitation existe, et la réponse à l'administrateur
-- est la même, que le compte existe ou non.
CREATE TABLE org_invitations (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    id         uuid NOT NULL,
    email      text NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(email)),
    role       text NOT NULL CHECK (role IN ('member', 'admin')),
    invited_by bigint REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, email)
);
CREATE INDEX org_invitations_email_idx ON org_invitations (email);
CALL lotor_enforce_org_rls('org_invitations');

-- Équipe « Général » de chaque organisation existante.
INSERT INTO teams (org_id, id, name)
SELECT o.id, gen_random_uuid(), CASE o.default_language WHEN 'en' THEN 'General' ELSE 'Général' END
  FROM organizations o;

INSERT INTO team_members (org_id, team_id, user_id, role, created_at)
SELECT m.org_id, t.id, m.user_id, CASE m.role WHEN 'viewer' THEN 'reader' ELSE m.role END, m.created_at
  FROM org_memberships m JOIN teams t ON t.org_id = m.org_id;

ALTER TABLE org_memberships DROP CONSTRAINT org_memberships_role_check;
UPDATE org_memberships SET role = 'member' WHERE role IN ('viewer', 'analyst');
ALTER TABLE org_memberships ADD CONSTRAINT org_memberships_role_check CHECK (role IN ('member', 'admin'));

-- Tout projet a une équipe ; une équipe qui a des projets ne peut pas être supprimée.
ALTER TABLE projects ADD COLUMN team_id uuid;
UPDATE projects p SET team_id = t.id FROM teams t WHERE t.org_id = p.org_id;
ALTER TABLE projects ALTER COLUMN team_id SET NOT NULL,
    ADD CONSTRAINT projects_team_fk FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id);
CREATE INDEX projects_team_idx ON projects (org_id, team_id);

-- Agent : équipe facultative (NULL : agent d'organisation, géré par ses seuls
-- administrateurs, qui peut servir les projets de toutes les équipes). Les agents serveur
-- existants rejoignent l'équipe de leur hôte (« Général »), les agents dépôt restent
-- d'organisation, puisqu'un agent dépôt sert toute l'organisation. Une équipe supprimée
-- rend ses agents à l'organisation.
ALTER TABLE agents ADD COLUMN team_id uuid,
    ADD CONSTRAINT agents_team_fk FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id) ON DELETE SET NULL (team_id);
UPDATE agents a SET team_id = t.id FROM teams t WHERE t.org_id = a.org_id AND a.kind = 'host';
CREATE INDEX agents_team_idx ON agents (org_id, team_id);

-- Jeton d'inscription : toujours une équipe, dont héritent le projet créé et l'agent
-- inscrit. Une équipe supprimée emporte ses jetons d'inscription.
ALTER TABLE enrollment_tokens ADD COLUMN team_id uuid;
UPDATE enrollment_tokens e SET team_id = t.id FROM teams t WHERE t.org_id = e.org_id;
ALTER TABLE enrollment_tokens ALTER COLUMN team_id SET NOT NULL,
    ADD CONSTRAINT enrollment_tokens_team_fk FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id) ON DELETE CASCADE;

-- Filtre d'équipe des lectures (ADR 0034) : la transaction déclare les équipes visibles
-- dans lotor.teams (db.Visible) : « * » pour toutes, sinon un tableau d'uuid. Sans
-- déclaration, current_setting échoue (paramètre inconnu sur une connexion neuve, ''
-- illisible comme tableau sur une connexion réutilisée) : un filtre oublié ne renvoie
-- jamais tous les projets. Fonction SQL simple, donc incorporée à la requête par le
-- planificateur ; CASE fixe l'ordre d'évaluation (« * » n'est jamais lu comme tableau).
CREATE FUNCTION lotor_team_visible(p_team uuid)
RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT CASE WHEN current_setting('lotor.teams') = '*' THEN true
                ELSE p_team = ANY (current_setting('lotor.teams')::uuid[]) END
$$;

-- Invitations en attente d'un compte, toutes organisations confondues (crossorg, ADR 0034) :
-- celles adressées à son e-mail, non expirées, d'organisations actives dont il n'est pas
-- déjà membre ; rien pour un compte désactivé. L'acceptation se fait ensuite dans InOrg,
-- sous la RLS, après une nouvelle vérification de l'e-mail.
CREATE FUNCTION lotor_user_invitations(p_user_id bigint)
RETURNS TABLE (org_id uuid, invitation_id uuid, slug text, name text, role text,
               created_at timestamptz, expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT i.org_id, i.id, o.slug, o.name, i.role, i.created_at, i.expires_at
      FROM users u
      JOIN org_invitations i ON i.email = lower(u.email)
      JOIN organizations o ON o.id = i.org_id
     WHERE u.id = p_user_id AND u.is_active = 1 AND o.archived_at IS NULL AND i.expires_at > now()
       AND NOT EXISTS (SELECT 1 FROM org_memberships m WHERE m.org_id = i.org_id AND m.user_id = u.id)
     ORDER BY i.created_at DESC, i.id
     LIMIT 50
$$;
