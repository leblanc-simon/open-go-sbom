-- 011_host_agent : agent serveur (T07). Demande de scan depuis l'interface, transmise au
-- prochain signal de vie, et dernier contexte d'hôte annoncé par l'agent (système,
-- noyau, architecture, durée du scan), affiché sur la fiche de l'agent et de son hôte.
-- Ces deux colonnes n'ont de sens que pour un agent serveur.

ALTER TABLE agents
    ADD COLUMN scan_requested_at timestamptz,
    ADD COLUMN host_context      jsonb CHECK (jsonb_typeof(host_context) = 'object' AND pg_column_size(host_context) <= 4096),
    ADD COLUMN host_context_at   timestamptz,
    ADD CONSTRAINT agents_host_only CHECK (kind = 'host' OR (scan_requested_at IS NULL AND host_context IS NULL)),
    ADD CONSTRAINT agents_host_context_at CHECK ((host_context IS NULL) = (host_context_at IS NULL));
