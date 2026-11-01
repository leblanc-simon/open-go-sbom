-- 018_triage : décisions de triage des constats et statut effectif (T14, ADR 0035).
--
-- Une décision vise un couple (composant, vulnérabilité) : pour un projet, le composant
-- exact (purl canonique) ; pour toute l'organisation, une famille de composants
-- (purl_base), éventuellement restreinte à une plage de versions vers. Elle s'applique
-- aux constats après la correspondance, y compris aux constats futurs du même couple.
-- Le journal des décisions est en ajout seul : une nouvelle décision, un retrait ou une
-- échéance ajoute une ligne ; la décision courante d'une clé est la plus récente.

CREATE TABLE triage_decisions (
    org_id         uuid NOT NULL,
    id             uuid NOT NULL,
    scope          text NOT NULL CHECK (scope IN ('project', 'org')),
    project_id     uuid,
    vuln_id        text NOT NULL CHECK (length(vuln_id) BETWEEN 1 AND 200),
    -- Projet : purl canonique du composant ; organisation : NULL.
    purl           text CHECK (length(purl) BETWEEN 1 AND 2048),
    purl_base      text NOT NULL CHECK (length(purl_base) BETWEEN 1 AND 2048),
    -- Organisation : plage vers normalisée, NULL pour toutes les versions.
    vers           text CHECK (length(vers) BETWEEN 1 AND 1024),
    -- set : décision ; withdraw : retrait de la décision de la clé ; expire : échéance
    -- d'un risque accepté, qui ramène le couple « à analyser ».
    action         text NOT NULL CHECK (action IN ('set', 'withdraw', 'expire')),
    status         text CHECK (status IN ('in_triage', 'affected', 'not_affected', 'false_positive', 'risk_accepted', 'fixed')),
    -- Justification VEX d'origine, telle quelle (OpenVEX ou CycloneDX).
    justification  text CHECK (justification IN (
        'component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path',
        'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist',
        'code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency',
        'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter',
        'protected_by_mitigating_control')),
    -- Déclaration d'impact ou commentaire de l'auteur.
    comment        text NOT NULL DEFAULT '' CHECK (length(comment) <= 4000),
    -- Risque accepté : dernier jour d'acceptation (UTC).
    expires_on     date,
    -- Compte qui a pris la décision (ou importé le VEX) ; NULL pour le système.
    author_user_id bigint REFERENCES users (id) ON DELETE SET NULL,
    -- Auteur lisible : e-mail du compte, « vex:<source> » pour un import, « system ».
    author_label   text NOT NULL CHECK (length(author_label) BETWEEN 1 AND 320),
    -- Décision remplacée par une échéance (action expire).
    expires_id     uuid,
    created_at     timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    FOREIGN KEY (org_id, expires_id) REFERENCES triage_decisions (org_id, id),
    CHECK ((scope = 'project') = (project_id IS NOT NULL AND purl IS NOT NULL)),
    CHECK (scope = 'org' OR vers IS NULL),
    CHECK ((action = 'withdraw') = (status IS NULL)),
    CHECK (action <> 'expire' OR (status = 'in_triage' AND expires_id IS NOT NULL)),
    CHECK (justification IS NULL OR status = 'not_affected'),
    CHECK (status IS DISTINCT FROM 'not_affected' OR justification IS NOT NULL OR comment <> ''),
    CHECK ((status = 'risk_accepted') = (expires_on IS NOT NULL))
);
-- Décisions d'un projet pour un composant, et d'une famille de composants : la
-- recherche des décisions applicables part toujours du couple (purl_base, vulnérabilité).
CREATE INDEX triage_decisions_pair_idx ON triage_decisions (org_id, purl_base, vuln_id, created_at);
CREATE INDEX triage_decisions_project_idx ON triage_decisions (org_id, project_id, created_at) WHERE scope = 'project';
CALL lotor_enforce_org_rls('triage_decisions');

DO $$
DECLARE
    app text := current_setting('lotor.app_role');
BEGIN
    -- Journal des décisions en ajout seul, comme le journal d'audit (migration 015) :
    -- CheckRuntimeRole le vérifie au démarrage.
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON triage_decisions FROM %I', app);
END
$$;

-- Statut effectif de chaque constat, tenu par internal/triage : décision du projet, sinon
-- de l'organisation, sinon « à analyser ». Recalculé à chaque décision et à la création
-- d'un constat ; lu par les écrans, les filtres et les exports sans recalcul.
ALTER TABLE findings
    ADD COLUMN triage_status text NOT NULL DEFAULT 'in_triage'
        CHECK (triage_status IN ('in_triage', 'affected', 'not_affected', 'false_positive', 'risk_accepted', 'fixed')),
    ADD COLUMN triage_decision_id uuid,
    ADD FOREIGN KEY (org_id, triage_decision_id) REFERENCES triage_decisions (org_id, id),
    ADD CHECK (triage_decision_id IS NOT NULL OR triage_status = 'in_triage');
CREATE INDEX findings_triage_idx ON findings (org_id, project_id, status, triage_status, risk DESC, id);
-- Constats dont une décision donne le statut (liste des décisions d'organisation).
CREATE INDEX findings_triage_decision_idx ON findings (org_id, triage_decision_id) WHERE triage_decision_id IS NOT NULL;
