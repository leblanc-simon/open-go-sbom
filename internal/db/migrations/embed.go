// Package migrations embarque les migrations SQL du projet, NNN_<sujet>.sql, appliquées
// par db.Migrate avec le rôle propriétaire.
//
// Une migration publiée sur main est immuable : sa somme SHA-256 est enregistrée dans
// lotor_schema_migrations et vérifiée à chaque démarrage. Une correction passe par une
// nouvelle migration. Chaque migration s'exécute dans la transaction du verrou de
// migration : pas d'instruction interdite en transaction (CREATE INDEX CONCURRENTLY…).
//
// Le rôle d'exécution est disponible dans le paramètre lotor.app_role, propre à la
// transaction (à lire avec current_setting et à citer avec format('%I')). Les privilèges
// par défaut posés par 001_init.sql lui accordent déjà l'accès aux tables, séquences et
// fonctions créées ensuite par le propriétaire. Toute table d'organisation appelle
// lotor_enforce_org_rls (RLS forcée, politique standard) ; la validation qui clôt la
// migration refuse sinon de démarrer.
package migrations

import "embed"

// FS contient les fichiers *.sql à la racine du paquet.
//
//go:embed *.sql
var FS embed.FS
