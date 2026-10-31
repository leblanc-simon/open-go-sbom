-- Rôles et base de développement. Mots de passe de développement uniquement.
CREATE ROLE ogsbom_owner LOGIN PASSWORD 'ogsbom_owner';
CREATE ROLE ogsbom_app LOGIN PASSWORD 'ogsbom_app' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE ogsbom OWNER ogsbom_owner;
REVOKE ALL ON DATABASE ogsbom FROM PUBLIC;
GRANT CONNECT ON DATABASE ogsbom TO ogsbom_app;
