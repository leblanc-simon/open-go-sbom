-- Rôles et base de développement. Mots de passe de développement uniquement.
-- BYPASSRLS : exigé par les fonctions inter-organisations (internal/db/crossorg).
CREATE ROLE lotor_owner LOGIN BYPASSRLS PASSWORD 'lotor_owner';
CREATE ROLE lotor_app LOGIN PASSWORD 'lotor_app' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE lotor OWNER lotor_owner;
REVOKE ALL ON DATABASE lotor FROM PUBLIC;
GRANT CONNECT ON DATABASE lotor TO lotor_app;
