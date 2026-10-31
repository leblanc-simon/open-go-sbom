# T01 — Socle du serveur

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 1 · MVP inventaire | T00 | À faire |

## Objectif

Un `ogsbom-server` qui démarre, se configure, migre sa base, sert une page d'accueil traduite
en thème clair et sombre, expose ses sondes et ses métriques, et s'arrête proprement.
Tout ce que les lots suivants réutilisent : configuration, base, rendu, assets, i18n, API.

## Périmètre

**Inclus**

- `internal/config` : `Config` composée (§ 6 de l'architecture), dont les fragments `TLS` et
  `Migration`, méthode `Validate()` aux messages explicites (pilote `postgres`, pool de
  migration d'au moins 2 connexions, cohérence TLS), `config.example.yaml` commenté.
- `internal/db` :
  - pool du rôle propriétaire ouvert le temps de migrer, puis pool d'exécution ;
  - attente bornée de la base au démarrage ;
  - contrôle du rôle d'exécution (ni superutilisateur, ni `BYPASSRLS`, ni propriétaire des
    tables), refus de démarrer sinon ;
  - `InTx` pour les tables globales et `InOrg` (§ 9 de l'architecture) pour les tables
    d'organisation, même si aucune n'existe encore ;
  - exécuteur de migrations du projet (table `ogsbom_schema_migrations` avec somme SHA-256,
    refus de démarrer si une migration publiée a changé), verrou de migration par
    `LOCK TABLE` sur une connexion dédiée ;
  - migration `001_init.sql` : privilèges par défaut du rôle d'exécution sur les tables et
    séquences futures du rôle propriétaire. Les appels aux `Migrate` d'authx et mfax sont
    branchés en T03, dans le même verrou.
- `deploy/compose.yaml` crée les deux rôles ; `docs/operations.md` décrit leur création
  et leurs droits pour une base existante.
- `internal/secret` : chiffrement AES-256-GCM, clés versionnées, rotation.
- Serveur HTTP public (chi), TLS natif facultatif, écoute de gestion séparée, arrêt propre
  sur SIGTERM.
- Les trois groupes de routes du § 14 : l'interface avec sa chaîne de middlewares jusqu'à
  la langue (la session arrive en T03) ; les groupes d'API montés vides, **sans** CSRF.
- `internal/render` : chargement des gabarits embarqués au démarrage (échec immédiat si un
  gabarit est invalide), layout, partials, FuncMap, pages d'erreur 404 et 500 traduites.
- Assets : concaténation des CSS embarquées en une feuille à empreinte, URL à empreinte pour
  les modules JS, en-têtes de cache.
- `web/static/css` : port des fondations du [design de référence](https://claude.ai/artifact/PPcixBYWkzQJ1XoEVco9Qj)
  (planche « Fondations — tokens » et feuille `project/ogs.css`) : `tokens.css` (couleurs,
  typographie, espacements, échelle de sévérité, KEV, origine IA, thèmes clair et sombre),
  `base.css`, en-tête, navigation, pied de page ; bascule de thème ; polices Atkinson
  Hyperlegible auto-hébergées (`web/static/fonts`). Les composants de la planche
  « Composants » sont portés au fur et à mesure des écrans qui les utilisent.
- `locales/en.yaml` et `fr.yaml` avec les clés du socle ; ordre de choix de la langue du
  § 18 (la préférence du compte se branche en T03) ; tests de complétude et d'usage.
- Infrastructure d'API : `api/openapi.yaml` initial, génération, erreurs RFC 9457, aide à la
  pagination par curseur, test « code généré à jour ».
- Gestion : `/healthz`, `/readyz` (selon les rôles actifs, § 20), `/metrics`.
- Assistant de test d'accessibilité réutilisable : analyse d'une page rendue (langue, titre,
  un seul `h1`, libellés de champs, textes alternatifs, lien d'évitement).

**Exclu** : comptes et sessions (T03), file de traitements (T02).

## Conception

- `cmd/ogsbom-server/main.go` ne fait que : charger la config, construire les dépendances,
  lancer les serveurs, attendre le signal.
- `secret.Box` : `Seal(plaintext) (ciphertext, keyID)` et `Open` ; la clé active chiffre, les
  anciennes déchiffrent. Le format du chiffré est versionné.
- En-têtes de sécurité : CSP du § 14, `Strict-Transport-Security` si TLS (natif ou déclaré
  par le mandataire de confiance), `X-Content-Type-Options`, `Referrer-Policy: same-origin`,
  `Permissions-Policy` restrictive.
- ADR « fonctions de gabarit dépendantes de la requête » : clonage par requête d'un jeu de
  gabarits jamais exécuté, ou traducteur et jeton CSRF passés dans les données de la page.
  Critères : coût mesuré par requête, simplicité des gabarits, impossibilité d'oublier la
  traduction.
- La bascule de thème mémorise le choix dans `localStorage` (protégé par `try/catch`) ;
  sans JS, le thème suit le système.

## Livrables

`ogsbom-server` démarrable, `config.example.yaml`, migration initiale, page d'accueil,
`api/openapi.yaml` initial, ADR des gabarits, `docs/operations.md` (installation de
développement, configuration, TLS ou mandataire inverse, sondes).

## Critères d'acceptation

- [ ] `ogsbom-server --help` liste toutes les variables `OGSBOM_*` avec leur description.
- [ ] Une configuration invalide arrête le démarrage avec un message qui nomme le champ.
- [ ] Sur une base vide, les migrations s'appliquent ; deux instances lancées en même temps
      ne migrent qu'une fois ; une migration publiée modifiée empêche le démarrage.
- [ ] Le serveur refuse de démarrer si le rôle d'exécution est superutilisateur, possède
      `BYPASSRLS` ou possède les tables.
- [ ] Une table de test sous RLS forcée : dans `InOrg(A)`, une requête sans filtre ne voit
      que les lignes de A et ne peut pas en écrire pour B ; hors `InOrg`, la requête échoue.
- [ ] La page d'accueil s'affiche en français et en anglais (`?lang=`), en thème clair et
      sombre, sans aucun script ni style en ligne.
- [ ] Les en-têtes de sécurité et la CSP sont présents sur toutes les réponses de
      l'interface ; une requête `POST` vers un groupe d'API n'est pas soumise au CSRF.
- [ ] `/readyz` renvoie une erreur tant que la base est injoignable.
- [ ] SIGTERM laisse finir les requêtes en cours dans un délai configurable.
- [ ] Une clé de traduction manquante dans une langue fait échouer les tests.

## Tests attendus

Unitaires : validation de config, `secret` (aller-retour, rotation, chiffré altéré refusé),
empreinte des assets, FuncMap. Intégration : migrations concurrentes et altérées, arrêt
propre, rendu des pages et assistant d'accessibilité.

## Points à trancher

- Valider la dépendance `prometheus/client_golang` pour `/metrics`.

## Journal

_À remplir pendant la réalisation._
