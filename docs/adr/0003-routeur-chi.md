# 0003 — Routeur chi

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

L'interface a trois groupes de routes aux chaînes de middlewares distinctes (interface,
API agent, API utilisateur) et des sous-routes par organisation (`/o/{slug}/…`). Le
routeur de la bibliothèque standard gère les motifs depuis Go 1.22, mais pas les groupes
ni le montage de sous-routeurs avec leurs middlewares.

## Décision

`github.com/go-chi/chi/v5` (v5.5.0 au moment de la décision), comme dans open-go-canivet.
Les handlers restent des `http.Handler` standards ; oapi-codegen génère l'adaptateur chi.

## Conséquences

Dépendance sans dépendance transitive. Les middlewares d'open-go-base, standards
(`func(http.Handler) http.Handler`), s'y branchent directement.

## Alternatives écartées

- `net/http.ServeMux` seul : groupes et montage à réécrire à la main.
- gorilla/mux, echo, gin : plus lourds, ou API non standard.
