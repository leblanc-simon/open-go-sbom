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
| T05 | #7 | Terminé | Décodage dans le worker, sous-processus écarté (ADR 0015) ; règles de l'inventaire (ADR 0016 : purl de packageurl-go, identification faible par élément, CPE hors empreinte, commit renvoyé = ensemble remplacé, courant = date de scan, refus stockés en `failed`, doublon de dépôt en 200) ; validation sans l'énumération des licences SPDX de CycloneDX à la réception ; bornes par défaut (32/64 Mio, profondeur 64, 50 000 composants, 5 min, 2 par organisation) ; directive `go` 1.26.8 (Syft) — tous **[à relire]** |
| T06 | #9 | Terminé | Base Grype commune en blocs dans PostgreSQL, téléchargement par `internal/download` (ADR 0017) ; correspondance hors transaction et écriture sous verrou, identifiants CVE, réanalyse par organisation sans nouvelle fonction `crossorg` (ADR 0018) ; jeu synthétique et autoanalyse par `go run` des commandes Syft et Grype (ADR 0019) ; valeurs par défaut `vulndb.*` ; mesures faites sur 4 cœurs, pas sur la machine de référence — tous **[à relire]** |
| T07 | #10 | Terminé | Envoi conditionnel confirmé par le serveur, Syft JSON, demande de scan remise une fois, muet sur le dernier inventaire pour un agent serveur (ADR 0020) ; unités, secrets, mTLS par middleware, paquets nfpm (ADR 0021) ; scan à la demande ouvert aux analystes ; valeurs par défaut ; cibles 5 min de CPU et 1 Gio par scan ; agent dépôt branché sur le client commun (adresse https exigée) — tous **[à relire]** |
| T08 | #8 | Terminé | Agent dépôt (ADR 0023) : webhook = signal, tête résolue auprès de la forge ; `git fetch --depth 1` du commit au lieu de `clone --single-branch` ; SBOM déterministe (ni numéro de série ni horodatage) ; Syft sans `go list` ni réseau ; échecs définitifs non retentés avant redémarrage ; secrets par `credential:<nom>` ou fichier 0600 ; jeton GitHub restreint à `contents: read` ; valeurs par défaut ; droits GitLab vérifiables seulement sur forge réelle — tous **[à relire]** |
| T09 | #12 | Terminé | Recherche (ADR 0024) : deux nouvelles fonctions `crossorg` de recherche par nom et empreinte (organisation lue dans `ogsbom.org_id`, contournent la RLS pour les index GIN), sous-chaîne puis trigrammes, bornes, export en flux borné en nombre et durée ; jetons personnels en table globale valables sur les organisations du compte, expiration obligatoire, sans session dans l'API (ADR 0025) ; comparateurs de Grype corrigés et plages vers maison (ADR 0026) ; défauts `user_api` ; écarts à la maquette ; mesures sur 4 cœurs — tous **[à relire]** |
| T10 | #11 | Terminé | Tableau de bord (ADR 0027) : constats des références actives des projets actifs ; statistiques réécrites toutes les heures sous la date du jour ; `project_daily_stats` en plus d'`org_daily_stats` ; pas de nouvelle fonction `crossorg` ; seuil « muet » de 7 jours pour toute l'interface ; périodes 30/90/365 j ; tuiles sans lien (pas de liste transverse avant T09) ; section « Alertes » et objectifs de délai renvoyés à T15 ; mesures sur 4 cœurs partagés — tous **[à relire]** |
| T11 (accessibilité) | à venir | En cours | Audit RGAA : 13 NC corrigées, 100 % des critères applicables ; page de confirmation commune pour les actions irréversibles (abandon d'un traitement compris) ; plan du site plutôt que la recherche pour 12.1 ; préfixe « Erreur : » sur tout écran en 4xx ; abréviations des sévérités — tous **[à relire]** |
| T11 (1/2) | à venir | En cours | Administration de l'instance (ADR 0028) : archive téléversée rangée dans PostgreSQL puis installée par un job, jeton CSRF en tête du formulaire présenté à csrfx, archive importée cible même plus ancienne, un import à la fois, état par instance (`vulndb_instances`), purge de toutes les archives non cibles avec confirmation ; `download_timeout` borne aussi le téléversement ; abandon d'un traitement sans confirmation ; test instable corrigé dans le test (bail simulé complet) ; codes de secours de mfax absents d'open-go-base, reportés à T18 — tous **[à relire]** |
| T11 (sécurité) | à venir | En cours | Revue de sécurité du lot 1 (14 constats, 0 haut ni critique) : 3 Medium, 7 Low et 2 Note corrigés, 2 Note acceptées, SEC-09 accepté jusqu'à T16 ; open-go-base v1.3.0 (PR #3 fusionnée, étiquette à pousser) ; verrouillage par compte sur le TOTP seul, réinitialisation du TOTP avec mot de passe temporaire, révocation d'office des jetons et code TOTP à leur création, durée absolue de session de 7 jours (ADR 0029) ; journal en ajout seul, quotas d'ingestion 200/jour/référence et 10 Gio/organisation, un export et un réencodage par compte (ADR 0030) ; CSRF lié à la session, `http.CrossOriginProtection`, cookies `__Host-` avec `cookie_secure: on` dans l'exemple, `allowed_namespaces` obligatoire pour l'agent dépôt (ADR 0031) — tous **[à relire]** |

## Actions pour l'utilisateur

Le mandataire git de la session refuse les pushs d'étiquettes (HTTP 403) : open-go-sbom
utilise des pseudo-versions d'open-go-base. À faire, dans l'ordre :

1. Pousser l'étiquette annotée `v1.1.0` d'open-go-base, créée localement par T03 sur le
   commit `b9ccc67` : `git -C ../open-go-base push origin v1.1.0`.
2. Pousser l'étiquette annotée `v1.2.0` d'open-go-base, créée localement par T04 sur le
   commit `3534c14` (`ratelimit.WithKeyFunc`, changement compatible) :
   `git -C ../open-go-base push origin v1.2.0`.
3. Pousser l'étiquette annotée `v1.3.0` d'open-go-base, créée localement par T11
   (revue de sécurité) sur le commit `9a7b91f` (PR #3 : verrouillage par compte de mfax,
   `Confirm`, `WithChallengeCookieName`, `csrfx.WithSessionBinding` ; changements
   compatibles) : `git -C ../open-go-base push origin v1.3.0`.
4. Remplacer la pseudo-version par l'étiquette dans open-go-sbom :
   `go get leblanc.io/open-go-base@v1.3.0 && go mod tidy` (même code que la
   pseudo-version actuelle `v1.0.2-0.20261031121913-9a7b91fdbbfe`). Ne pas utiliser
   `v1.1.0` ni `v1.2.0` : il leur manque `WithKeyFunc` ou le verrouillage de mfax.

## Organisation

- Chaque lot est réalisé par un agent au contexte neuf, qui lit `CLAUDE.md`,
  l'architecture, `specs/lecons.md`, sa fiche et le Journal des lots dont il dépend.
- Les lots indépendants avancent en parallèle (T02 et T03 ; T06, T07 et T08 ; T09 et T10),
  chacun sur sa branche `lot/<id>-<sujet>` et sa PR.
- Une PR est fusionnée en « squash » dès que la CI est verte et les critères cochés.
