// Package gen contient le client de l'API des agents, généré depuis api/openapi.yaml par
// oapi-codegen. Il n'est jamais modifié à la main : make generate le régénère.
package gen

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../api/openapi.yaml
