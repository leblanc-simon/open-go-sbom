// Package db ouvre les pools PostgreSQL, applique les migrations et fournit les
// transactions : InOrg pour toute donnée d'organisation (RLS), InTx pour les seules tables
// globales.
//
// # Deux rôles, deux pools
//
// Le rôle propriétaire possède le schéma et migre ; le rôle d'exécution fait tourner
// l'application avec SELECT, INSERT, UPDATE et DELETE seulement (privilèges par défaut de
// 001_init.sql). Au démarrage :
//
//	owner, _ := db.Open(cfg.Migration.DSN, db.PoolConfig{MaxOpenConns: 2})
//	_, err := db.Migrate(ctx, owner, db.MigrateOptions{AppRole: appRole})
//	owner.Close() // le pool du propriétaire ne vit que le temps de migrer
//
//	app, _ := db.Open(cfg.Database.DSN, poolConfig)
//	err = db.WaitReady(ctx, app, timeout, logger)
//	err = db.CheckRuntimeRole(ctx, app) // refuse superutilisateur, BYPASSRLS, propriétaire
//	err = db.VerifySchema(ctx, app, nil)
//	pool := db.NewPool(app)
//
// # Transactions
//
// Un store prend un *Pool et un tenant.OrgID en premier paramètre métier :
//
//	func (s *Store) Rename(ctx context.Context, org tenant.OrgID, id uuid.UUID, name string) error {
//		return s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
//			_, err := tx.ExecContext(ctx, `UPDATE projects SET name = $2 WHERE id = $1`, id, name)
//			return err
//		})
//	}
//
// InOrg déclare l'organisation par set_config('lotor.org_id', …, true) : la RLS limite
// alors lecture et écriture à cette organisation, même si la requête oublie son filtre, et
// toute requête sur une table d'organisation hors InOrg échoue. InTx sert aux tables
// globales (jobs, vulnérabilités…). Ni Tx ni OrgTx n'exposent Commit : la transaction est
// validée si la fonction renvoie nil, annulée sinon. Aucune transaction ne doit traverser
// un appel réseau. Querier est l'interface commune, pour travailler dans la transaction
// de l'appelant. Pour relire un tableau PostgreSQL, Array.
//
// # Équipes visibles
//
// Une lecture faite pour un compte ajoute l'option Visible(acc.Visibility()) : InOrg
// déclare alors les équipes visibles (set_config('lotor.teams', …, true)), et la requête
// filtre ses projets par la fonction SQL lotor_team_visible(team_id). Sans cette option,
// lotor_team_visible échoue : un filtre d'équipe oublié par l'appelant ne renvoie jamais
// tous les projets (ADR 0034). Ce filtre s'ajoute à la RLS, à l'intérieur de
// l'organisation déclarée ; il ne la remplace pas.
//
// # Migrations
//
// Migrate applique les fichiers de internal/db/migrations sous un verrou (LOCK TABLE
// lotor_schema_migrations IN EXCLUSIVE MODE, sur une connexion dédiée), dans une seule
// transaction, enregistre leur somme SHA-256 et refuse une migration publiée modifiée.
// Les migrations d'authx puis de mfax sont jouées sous ce verrou, avant celles du projet. Avant
// de valider, CheckOrgIsolation refuse toute table d'organisation sans la RLS standard.
package db
