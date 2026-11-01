// Package llm abstrait les fournisseurs de modèles de langage de l'agent dépôt (T12) :
// messages, outils, réponse et consommation, derrière l'interface Provider, et la boucle
// d'appels d'outils (Run) qui borne une analyse par un budget de tours et de jetons.
//
// Deux implémentations : Anthropic, par le SDK Go officiel construit sans aucune valeur
// lue dans l'environnement (clé, adresse et en-têtes viennent de la configuration de
// l'agent, ADR 0042), et Ollama, modèle local servi par son API HTTP, sans SDK. Le
// sous-paquet llmtest fournit un faux fournisseur scénarisé et un enregistreur des
// échanges pour les tests déterministes.
//
// Le paquet ne lit aucun fichier et n'exécute rien : ce qu'un modèle reçoit est
// exactement ce que l'appelant met dans la Request (prompt système, puis résultats des
// outils qu'il a lui-même exécutés). Run ne fait qu'acheminer les appels d'outils vers
// les Handler de l'appelant ; un outil inconnu reçoit une erreur, jamais un repli.
package llm
