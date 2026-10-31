// Package gen contient le code généré depuis api/openapi.yaml par oapi-codegen. Il n'est
// jamais modifié à la main : make generate le régénère, make generate-check vérifie en CI
// qu'il est à jour.
package gen

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../api/openapi.yaml
//go:generate go tool oapi-codegen -config agent-server.yaml ../../../api/openapi.yaml
