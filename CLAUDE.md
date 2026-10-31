# CLAUDE.md

Ce fichier guide Claude Code lorsqu'il travaille sur ce dépôt.

## Projet

**open-go-sbom** : plateforme open source de gestion de SBOM par projet (dépôt git ou
serveur). Deux agents produisent les SBOM (agent dépôt avec enrichissement IA, agent serveur
en Go sans IA) ; un serveur central les historise, les analyse chaque jour avec Grype, et
offre recherche transverse, triage et tableaux de bord. Multi-organisation, en Go, sur
[`leblanc.io/open-go-base`](../open-go-base) et PostgreSQL. Licence WTFPL.

## Documents de référence, dans cet ordre

1. [`docs/cahier-des-charges.md`](docs/cahier-des-charges.md) — le besoin et les décisions
   produit.
2. [`specs/architecture.md`](specs/architecture.md) — **fait autorité** sur l'architecture,
   les noms et les conventions.
3. [`specs/README.md`](specs/README.md) — les 27 lots techniques, leur ordre, leur statut,
   la façon de travailler et la définition de « terminé ».
4. `specs/lots/Txx-*.md` — la fiche du lot en cours, et le Journal des lots dont il dépend.

## État actuel

Aucun code. Prochain lot : [T00 — Fondations](specs/lots/T00-fondations.md).

## Règles de travail

- **La qualité prime sur la vitesse.** Pas de raccourci, pas de dette reportée.
- Un lot à la fois, sur une branche `lot/<id>-<sujet>`, fusionné par demande de fusion.
- Avant d'écrire du code : proposer un plan, et faire valider par l'utilisateur toute
  nouvelle dépendance tierce, tout écart à `architecture.md` et tout « point à trancher ».
- Toute décision structurante donne un ADR dans `docs/adr/` et, si besoin, une mise à jour
  d'`architecture.md` dans le même commit.
- En fin de lot : critères cochés, Journal de la fiche rempli, statut mis à jour dans
  `specs/README.md`, `make ci` vert.
- open-go-base est un autre dépôt (`../open-go-base`) : y proposer une évolution, ne pas la
  faire sans accord.

## Conventions qui reviennent sans cesse

- Code en anglais ; commentaires et documentation en français ; commentaires réservés au
  « pourquoi » non évident.
- Isolement des organisations (§ 9 de l'architecture) : RLS forcée sur toute table
  d'organisation, accès uniquement par `db.InOrg` (jamais `InTx`), `tenant.OrgID` en
  paramètre, clés étrangères composites, 404 pour une ressource d'une autre organisation,
  tests d'isolement par route et tests SQL de RLS. Les seules lectures
  inter-organisations passent par `internal/db/crossorg`.
- Deux rôles PostgreSQL : le propriétaire migre, l'application tourne avec un rôle qui ne
  peut pas contourner la RLS (vérifié au démarrage).
- Anchore (Syft, Grype, Grant) importé uniquement par ses adaptateurs (§ 4 de
  l'architecture, vérifié par `internal/archtest`).
- Traduction : aucune chaîne visible en dur ; clés anglaises `écran.élément` ; racines
  transverses `format.*`, `status.*`, `severity.*`, `validation.*`, `error.*` ; le JS reçoit
  ses libellés traduits via des attributs `data-`.
- Front sans npm ni bundler : `html/template`, modules ES natifs, CSS natif imbriqué
  (modificateur BEM `&.bloc--modificateur`, déclarations avant les règles imbriquées,
  `@media` imbriqués dans le composant). Aucun script ni style en ligne (CSP stricte).
- Migrations `internal/db/migrations/NNN_<sujet>.sql`, immuables une fois sur `main` : leur
  somme SHA-256 est vérifiée au démarrage.
- Comptes : authx ne fait que lire `users` ; c'est `internal/account` qui crée et modifie
  les comptes (`authx.HashPassword`, `must_change_pwd`).
- Évolutions attendues d'open-go-base : § 23 de l'architecture.
- TOTP obligatoire pour les comptes locaux : ne jamais utiliser
  `mfax.WithOptionalEnrollment()`.
- Jamais de mot de passe, jeton, secret ni contenu de SBOM dans les journaux.
- Jobs idempotents ; mise en file dans la transaction qui produit la donnée.

## Commandes

Disponibles après T00 (à mettre à jour avec le `Makefile` réel) :

```bash
make ci                 # fmt-check, vet, staticcheck, govulncheck, tests -race, intégration, archtest
make test-integration   # nécessite PostgreSQL : docker compose -f deploy/compose.yaml up -d
make generate           # code généré depuis api/openapi.yaml
make build              # bin/ogsbom-server, bin/ogsbom-host-agent, bin/ogsbom-repo-agent
```
