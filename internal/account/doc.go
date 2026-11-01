// Package account crée et modifie les comptes (seul écrivain de la table users d'authx) et
// enregistre la méthode d'authentification de chaque session.
//
// Le second facteur est obligatoire. Ses codes de secours (open-go-base mfax, table
// mfa_recovery_codes, T18) sont générés et vérifiés par mfax ; ce paquet les supprime avec le
// TOTP (réinitialisation par un administrateur, procédure de secours, ReconfigureTOTP à la
// demande du titulaire).
package account
