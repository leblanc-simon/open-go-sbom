# 0038 — Différences d'instantanés : par couple d'ensembles, appariement par purl_base, effet sur la sécurité calculé à la lecture

- Statut : Accepté
- Date : 2026-11-01
- Lot : T17

## Contexte

Le cahier des charges (§ 7, § 8) demande la différence entre deux instantanés : composants
ajoutés, retirés, montés ou descendus de version, et, pour la sécurité, les constats
introduits et résolus par un instantané. La fiche T17 impose que deux composants de même
`purl_base` et de versions différentes forment une montée ou une descente, et que la
différence soit stockée par couple d'ensembles d'inventaire (deux instantanés au même
ensemble n'ont rien à calculer). Les ensembles sont déjà adressés par contenu (ADR 0016) :
un nouveau commit sans changement de dépendances réutilise l'ensemble de son prédécesseur.

## Décision

### Stockage

- Tables d'organisation `set_diffs` (couple `from_set_id` → `to_set_id`, décomptes par
  nature, date de calcul) et `set_diff_items` (nature, `purl_base`, ancien et nouveau
  composant, approximation), sous la RLS standard, clés composites, supprimées en
  cascade avec l'un de leurs ensembles (migration 017).
- Seuls les couples d'**instantanés consécutifs** d'une référence (date de scan, puis
  identifiant, l'ordre de `ref_current`) sont enregistrés. Le job `inventory.diff`
  (charge `{"ref_id"}`, clé `diff:<ref>`) est mis en file dans la transaction de
  l'ingestion qui crée ou remplace un instantané ; il cherche par une fenêtre `lag()` les
  couples consécutifs sans différence et les calcule, un par transaction. Idempotent : un
  couple déjà enregistré n'est pas recalculé (`ON CONFLICT DO NOTHING`). Un instantané
  arrivé dans le désordre, un commit remplacé ou un historique réduit par la rétention
  (ADR 0039) créent de nouveaux couples : la rétention remet le job en file pour chaque
  référence dont un couple manque, ce qui rattrape aussi les instantanés antérieurs à T17.
- Une comparaison quelconque (deux instantanés d'un même projet, de références
  différentes au besoin, dans un sens ou dans l'autre) lit la différence enregistrée si le
  couple d'ensembles l'a, sinon la calcule à la demande sans l'enregistrer : le stockage
  reste borné par l'historique.

### Calcul

- SQL ne renvoie que les composants présents d'un seul côté (jointure externe des deux
  ensembles), Go les range : par `purl_base`, les versions retirées et ajoutées sont
  triées selon l'écosystème (`internal/version`, comparateurs de Grype, ADR 0026) puis
  appariées dans l'ordre ; chaque couple est une montée ou une descente, le reste des
  ajouts ou des retraits.
- Une même version présente des deux côtés (qualificatifs changés : architecture,
  distribution) n'est ni une montée ni une descente : elle reste un retrait et un ajout.
- Deux versions incomparables dans leur écosystème, puis en semver générique, sont
  ordonnées par leurs chaînes, et le changement est marqué « approché » (écran, API).

### Effet sur la sécurité

- Calculé à la lecture, jamais stocké : les constats évoluent avec chaque nouvelle base
  de vulnérabilités, un effet enregistré vieillirait. Une requête lit les constats de la
  référence de départ sur les composants qu'elle seule contient (retirés ou anciennes
  versions) et ceux de la référence d'arrivée sur les composants qu'elle seule contient ;
  une vulnérabilité présente des deux côtés pour un même `purl_base` n'est ni résolue ni
  introduite. Une montée qui corrige une CVE donne donc un « constat résolu », une montée
  qui ne la corrige pas n'en donne aucun.
- Un constat résolu parce que la base ne juge plus le composant vulnérable
  (`not_matched`) n'est pas compté : ce n'était pas une vulnérabilité.
- Si l'instantané d'arrivée est l'instantané courant et que son ensemble n'est pas encore
  analysé (`ref_analyses`), l'effet est signalé incomplet.
- 200 constats au plus de chaque côté, par risque décroissant ; les totaux comptent tout.

### Lecture

- La lecture d'un instantané donne son précédent (sous-requête latérale sur
  `snapshots_ref_idx`) et le décompte enregistré : la frise affiche les changements de
  chaque instantané sans calcul.
- Écrans : frise des instantanés d'une référence (décomptes, lien de comparaison),
  formulaire « Comparer deux instantanés » (50 derniers instantanés par référence),
  écran `/o/{slug}/projects/{project}/compare?from=&to=&kind=` (décomptes, effet sur la
  sécurité, changements filtrés et paginés, inversion). Droit `project.view`, ressource
  projet (ADR 0034) : les lectures sont indexées par le projet que la garde a vérifié.
- API utilisateur : `GET /api/v1/orgs/{org}/projects/{project}/snapshots` et
  `GET /api/v1/orgs/{org}/projects/{project}/compare`, mêmes données ; le projet est
  résolu avec la visibilité du propriétaire du jeton (404 hors de ses équipes).

## Conséquences

- Un instantané qui ne change rien (même ensemble) ne coûte aucune ligne de différence.
- Les deux ingestions qui écrivent une référence enchaînent un seul job de différences
  (clé d'unicité) ; le calcul ne bloque jamais l'ingestion.
- L'effet sur la sécurité dépend des analyses passées : un ensemble jamais analysé
  (instantané remplacé avant son analyse) n'a pas de constats ; l'écran le dit pour
  l'instantané courant. Le tri des constats (T14) pourra en tenir compte (faux positif).

## Alternatives écartées

- **Différence calculée à l'ingestion, dans la transaction de l'instantané** : elle
  alourdirait chaque décodage (jusqu'à deux fois 50 000 composants à apparier) et
  allongerait le verrou de la référence ; le job séparé garde l'ingestion rapide.
- **Différence entièrement en SQL** : l'appariement par version demande la comparaison
  par écosystème, qui vit en Go (`internal/version`) ; une comparaison de chaînes
  classerait « 4.17.9 » après « 4.17.21 ».
- **Enregistrer toutes les comparaisons demandées** : stockage non borné, et rien à
  gagner pour des couples rarement relus.
- **Effet sur la sécurité tiré de `finding_events`** (événements « ouvert » et « résolu »
  portant l'instantané) : une réanalyse sur une nouvelle base produit aussi des
  événements sur le même instantané, si bien qu'une CVE publiée après coup passerait pour
  « introduite » par l'instantané ; et ces événements perdent leur instantané à la
  rétention.
