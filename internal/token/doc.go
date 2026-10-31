// Package token tire et lit les jetons de l'instance (§ 10 de l'architecture, ADR 0014) :
// lotor_<nature>_<identifiant public>_<secret>, natures agt (agent), enr (inscription d'un
// agent serveur) et pat (accès personnel). Seul le SHA-256 du secret est stocké ; la
// comparaison se fait en temps constant (SecretHash.Matches).
//
//	t, err := token.New(token.Personal)         // t.Plaintext montré une seule fois
//	pub, hash, err := token.Parse(token.Personal, raw)
package token
