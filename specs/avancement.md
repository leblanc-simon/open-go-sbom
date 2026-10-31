# Avancement du lot 1

Journal de bord de la réalisation autonome du lot 1 (T00 à T11), demandée le
31 octobre 2026. Chaque entrée renvoie au Journal de la fiche, qui fait foi pour le détail
des décisions. Les décisions prises sans validation explicite de l'utilisateur sont
marquées **[à relire]**.

| Lot | PR | Statut | Décisions à relire |
| --- | --- | --- | --- |
| T00 | — | Terminé | `modernc.org/sqlite` ajouté au § 5 **[à relire]** ; OpenAPI 3.1 ; SQL à la main |
| T01 | #3 | Terminé | Migrations et rôles (ADR 0010) ; fragments de config au fil des lots, fragment `HTTP` ; `Seal`/`Open` avec données associées ; en-têtes de sécurité (`base-uri`, HSTS sans sous-domaines) ; thème `light-dark()` + cookie ; polices droites seulement ; pied de page hors planche — tous **[à relire]** |
| T02 | #4 | Terminé | Conception de la file (ADR 0011 : horloge Go, `synchronous_commit = off` pour les transitions d'état, plafond strict, libération sans tentative comptée…) ; valeurs par défaut des workers ; correction de `PoolConfig.MaxIdleConns` (T01) — **[à relire]** |
| T03 | #5 | Terminé | Propriétaire `BYPASSRLS` pour `crossorg` (ADR 0012) ; secrets TOTP chiffrés, `secrets.keys` obligatoire (ADR 0013) ; secours par ticket (deux variables) ; TOTP avant changement de mot de passe ; 404 pour l'administration, 403 dans l'organisation ; `jobs.org_id` sans clé étrangère ; open-go-base en pseudo-version, étiquette `v1.1.0` à pousser — tous **[à relire]** |
| T04 | #6 | Terminé | Format des jetons et deux fonctions `crossorg` pour l'organisation d'un jeton (ADR 0014) ; `ratelimit.WithKeyFunc` dans open-go-base (étiquette `v1.2.0` à pousser) et suppression d'`internal/ratelimit` ; refus de jetons limités par IP ; hôte déjà suivi refusé à l'inscription ; jeton d'agent d'inscription sans expiration ; « muet » sur le dernier contact ; écriture réservée aux administrateurs ; valeurs par défaut — tous **[à relire]** |

## Actions pour l'utilisateur

Le mandataire git de la session refuse les pushs d'étiquettes (HTTP 403) : open-go-sbom
utilise des pseudo-versions d'open-go-base. À faire, dans l'ordre :

1. Pousser l'étiquette annotée `v1.1.0` d'open-go-base, créée localement par T03 sur le
   commit `b9ccc67` : `git -C ../open-go-base push origin v1.1.0`.
2. Pousser l'étiquette annotée `v1.2.0` d'open-go-base, créée localement par T04 sur le
   commit `3534c14` (`ratelimit.WithKeyFunc`, changement compatible) :
   `git -C ../open-go-base push origin v1.2.0`.
3. Remplacer la pseudo-version par l'étiquette dans open-go-sbom :
   `go get leblanc.io/open-go-base@v1.2.0 && go mod tidy` (même code que la
   pseudo-version actuelle `v1.0.2-0.20261031043924-3534c1429b63`). Si seule `v1.1.0` est
   poussée, ne pas l'utiliser : elle n'a pas `WithKeyFunc`.

## Organisation

- Chaque lot est réalisé par un agent au contexte neuf, qui lit `CLAUDE.md`,
  l'architecture, `specs/lecons.md`, sa fiche et le Journal des lots dont il dépend.
- Les lots indépendants avancent en parallèle (T02 et T03 ; T06, T07 et T08 ; T09 et T10),
  chacun sur sa branche `lot/<id>-<sujet>` et sa PR.
- Une PR est fusionnée en « squash » dès que la CI est verte et les critères cochés.
