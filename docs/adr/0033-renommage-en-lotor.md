# 0033 — Renommage du projet en lotor

- Statut : Accepté
- Date : 2026-10-31
- Lot : hors lot (demande de l'utilisateur, après T11)

## Contexte

L'utilisateur renomme le projet « open-go-sbom » en **lotor** et fournit son identité
visuelle (queue de raton laveur, *Procyon lotor*). Toute notion d'open-go-sbom ou du
préfixe `ogsbom` doit disparaître : module, commandes, préfixe d'environnement, objets
SQL, jetons, unités et paquets. Aucune version n'est publiée (`v0.1.0` pas encore posée)
et aucune installation n'existe hors des bases jetables des tests et de la recette.

## Décision

- **Correspondance unique**, appliquée à tout le dépôt (code, SQL, documentation,
  historique des fiches et des ADR) : `open-go-sbom` → `lotor`, `ogsbom` → `lotor`,
  `OGSBOM` → `LOTOR`. Le nom s'écrit en minuscules, comme sur le logo.
- Ce qui en découle :
  - module `leblanc.io/lotor` ;
  - commandes `lotor-server`, `lotor-host-agent`, `lotor-repo-agent` ;
  - préfixe d'environnement `LOTOR_` ;
  - utilisateur système `lotor-agent`, répertoires `/etc/lotor*` et `/var/lib/lotor*` ;
  - rôles d'exemple `lotor_owner` et `lotor_app` ;
  - fonctions SQL `lotor_*`, paramètre de session `lotor.org_id`, table
    `lotor_schema_migrations` ;
  - jetons `lotor_agt_…`, `lotor_enr_…`, `lotor_pat_…` ;
  - métriques `lotor_*`, propriétés CycloneDX `lotor:*`, cookies et classe CSS racine.
- **Migrations réécrites en place**, par exception à la règle d'immuabilité
  ([ADR 0010](0010-migrations-et-roles-postgresql.md)). Aucune base ne les a appliquées
  hors des tests, et une migration correctrice aurait laissé l'ancien nom dans 15 fichiers
  et recréé toutes les politiques RLS pour rien. La règle s'applique de nouveau dès ce
  changement fusionné.
- **Identité visuelle** : le jeu complet fourni est rangé dans `docs/logo/` (SVG, PNG,
  `favicon.ico`). L'interface sert `favicon.svg` (icône et marque de l'en-tête),
  `favicon-32.png` en repli et `apple-touch-icon.png`. Le README affiche l'avatar, dont le
  fond clair reste lisible en thème sombre, contrairement au logotype à texte foncé.
- La couleur d'accent de l'interface (sarcelle) ne change pas : le logo ne l'impose pas,
  et la changer reprendrait l'audit des contrastes.

## Conséquences

- Une base créée avant ce changement ne démarre plus (sommes des migrations différentes) ;
  aucune n'existe hors des tests. Les jetons `ogsbom_…` ne sont plus reconnus.
- Le dépôt GitHub et le chemin d'import doivent suivre : l'utilisateur renomme le dépôt
  en `leblanc-simon/lotor` (les liens du dépôt pointent déjà vers ce nom ; GitHub redirige
  l'ancien) et publie, si `leblanc.io` sert des métadonnées `go-import`, celle de
  `leblanc.io/lotor`.
