// Package forge accède aux forges pour l'agent dépôt : identification d'un dépôt par son
// URL, identifiants de clonage, résolution d'une référence en commit, comparaison de deux
// commits et vérification des webhooks de push.
//
// Deux implémentations : GitHub par une GitHub App (JWT RS256 signé avec la bibliothèque
// standard, jeton d'installation limité à la lecture du contenu et mis en cache jusqu'à son
// expiration, webhooks signés par X-Hub-Signature-256) et GitLab par un compte de service
// (jeton d'accès, webhooks authentifiés par X-Gitlab-Token comparé en temps constant).
// Forgejo s'ajoutera derrière la même interface Provider.
//
// Les secrets (clé privée, jetons, secrets de webhook) ne sont jamais journalisés ni
// placés dans une URL : Credentials se masque à l'affichage, et les erreurs ne citent que
// la méthode, le chemin et le statut des appels.
package forge
