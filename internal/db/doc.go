// Package db ouvre le pool PostgreSQL, applique les migrations et fournit les transactions :
// InOrg pour toute donnée d'organisation (RLS), InTx pour les seules tables globales.
package db
