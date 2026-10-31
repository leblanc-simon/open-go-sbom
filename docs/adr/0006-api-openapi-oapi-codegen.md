# 0006 — API conçue en OpenAPI 3.1, code généré par oapi-codegen

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

Les deux agents et le serveur partagent un contrat ; un client tiers (scripts, CI) doit
pouvoir s'y fier. Exploration menée avec oapi-codegen v2.8.1 (kin-openapi v0.142.0) :

- le README annonce le support d'OpenAPI 3.1 (« initial », PR #2336) : nullabilité
  `type: [T, "null"]`, énumérations `oneOf` + `const`, webhooks ;
- un même schéma écrit en 3.1.0 (`type: [string, "null"]`, `exclusiveMinimum: 0`) et en
  3.0.3 (`nullable: true`, `minimum: 1`) génère le même type Go
  (`Name *string`, `N int`) ;
- les générateurs `types`, `std-http-server` et `chi-server` fonctionnent sur ces fichiers.

## Décision

- `api/openapi.yaml` est la source unique, écrite en **OpenAPI 3.1.0**.
- oapi-codegen v2.8.1 en directive `tool` génère le serveur (interface stricte, adaptateur
  chi) dans `internal/api/gen` et le client des agents dans `internal/agentclient/gen` ;
  directives `//go:generate` dans ces paquets, `make generate`, et `make generate-check`
  en CI.
- Paquet d'exécution : `github.com/oapi-codegen/runtime` (v1.8.0), ajouté avec le premier
  code généré (T04).
- Si une construction 3.1 n'est pas gérée, on l'écrit autrement en 3.1 plutôt que de
  revenir à 3.0 ; un retour à 3.0 demanderait un nouvel ADR.

## Conséquences

Le code généré n'est jamais modifié à la main ; les écarts entre contrat et
implémentation sont des erreurs de compilation.

## Alternatives écartées

- Code d'abord, spécification extraite : le contrat suit l'implémentation au lieu de la
  guider.
- ogen : génère son propre routeur et ses types d'erreurs, moins proche de `net/http`.
