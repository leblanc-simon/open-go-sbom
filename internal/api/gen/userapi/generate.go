// Package userapi contient le serveur de l'API utilisateur (/api/v1/orgs/{org}/*) et ses
// types, générés depuis api/openapi.yaml par oapi-codegen. Il n'est jamais modifié à la
// main : make generate le régénère, make generate-check vérifie en CI qu'il est à jour.
package userapi

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../../api/openapi.yaml
