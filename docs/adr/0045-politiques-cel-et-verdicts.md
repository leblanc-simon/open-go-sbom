# 0045 — Politiques en CEL, violations datées et verdict d'un instantané

- Statut : Accepté
- Date : 2026-11-01
- Lot : T15

## Contexte

Le cahier des charges demande des règles déclaratives (KEV sur un projet de production,
critique avec correctif disponible depuis plus de 30 jours, licence AGPL dans un produit
distribué, agent muet depuis 7 jours), évaluées après chaque analyse et chaque jour, dont le
verdict est publié comme statut de commit. La dépendance `github.com/google/cel-go` a été
validée par l'utilisateur le 1er novembre 2026. La fiche exige qu'une règle invalide ou trop
coûteuse soit refusée à l'enregistrement, qu'aucune règle ne s'exécute sans limite de coût,
et que les notifications soient dédoublonnées.

## Décision

- **Bibliothèque** : `cel.dev/cel-go` v0.32.0. C'est `github.com/google/cel-go` sous son
  nouveau chemin de module : le projet a changé de chemin à v0.32.0 (le chemin GitHub est
  figé à v0.31.0), et v0.32.0 (19 août 2026) est la version la plus récente publiée depuis
  plus de deux semaines (v0.33.x date de la dernière semaine). Seule dépendance transitive
  nouvelle : `github.com/antlr4-go/antlr/v4` v4.13.1 (analyseur), `cel.dev/expr` étant
  déjà dans le graphe. **[à relire]**
- **Deux sujets** : une règle porte sur un constat ouvert (variables `project`,
  `component`, `finding`, `triage`, `ref`, `now`) ou sur un agent (`agent`, `now`). Le
  contexte est **typé** (structures Go déclarées à CEL par `ext.NativeTypes`, noms par
  étiquettes `cel`) : un champ inconnu, une erreur de syntaxe ou de type, un résultat non
  booléen sont refusés à la compilation avec la ligne et la colonne, traduits
  (`validation.policy_*`) et accompagnés du message technique de CEL. `finding.actionable`
  vaut vrai pour les statuts « à analyser » et « affecté » seulement (ni non affecté, ni
  faux positif, ni risque accepté, ni corrigé), pour que les modèles ne relancent pas une
  alerte que le triage a traitée. **[à relire]**
- **Coût borné** : coût estimé (tailles supposées de 100 éléments pour les chaînes, listes
  et tables) au plus 50 000 à l'enregistrement, et même limite de coût réel à chaque
  évaluation (`cel.CostLimit`), interruption vérifiée dans les compréhensions ; expression
  de 4 000 caractères au plus ; 100 politiques par organisation.
- **« Correctif disponible depuis »** : nouvelle colonne `findings.fixed_seen_at`, posée par
  l'analyse quand un correctif apparaît sur le constat, effacée s'il disparaît ; les constats
  existants partent de leur première détection. La base Grype ne donne pas la date de
  publication d'un correctif : c'est la date à laquelle lotor l'a vu, borne inférieure.
  **[à relire]**
- **Violations** (`policy_violations`) : une ligne par couple (règle, sujet) tant qu'il
  satisfait la règle (index unique partiel), prolongée à chaque évaluation, résolue dès qu'il
  ne la satisfait plus ; une nouvelle violation ne s'ouvre qu'ensuite. Désactiver une règle
  ou changer son expression résout ses violations ; la supprimer les supprime. Une
  évaluation qui échoue sur une donnée (clé absente…) compte comme non violée et note sa
  dernière erreur sur la règle.
- **Évaluation** : job `policy.evaluate_project` par projet (constats ouverts des
  références actives ; projet archivé : tout est résolu), mis en file dans la transaction de
  l'analyse (`finding.Options.OnAnalyzed`, priorité haute), dans celle d'un changement de
  triage (`triage.Options.OnChange`) et chaque jour ; `policy.evaluate_org` évalue les
  agents et met en file chaque projet, après un changement de règle et chaque jour
  (`policy.evaluate_all` à 02:00 UTC). Verrou consultatif par projet. Aucune nouvelle
  fonction `crossorg` : la liste des organisations vient de `lotor_list_organizations`.
- **Verdict** d'un instantané (`GET /api/v1/agent/snapshots/{id}/verdict`, instantané de
  l'agent qui l'a envoyé) : en attente tant que l'ensemble de l'instantané n'est pas celui
  de la dernière analyse de sa référence ou que cette analyse n'est pas évaluée
  (`policy_evaluations`) ; non conforme s'il reste une violation ouverte d'une règle
  **bloquante** sur la référence ; conforme sinon (avec le nombre d'avertissements). Le
  résumé est traduit dans la langue de l'organisation et borné à 140 caractères ; le lien
  mène aux constats du projet quand `notify.public_url` est configuré. Les règles d'agent
  ne bloquent jamais un commit.
- **Modèles** : KEV sur un projet étiqueté `env=production`, critique avec correctif vu
  depuis plus de 30 jours, agent muet depuis 7 jours (`agent.silent_days`, règle de
  `agent.Activity.Since`) ; le modèle « licence AGPL » est affiché mais indisponible jusqu'à
  T20 (aucune donnée de licence dans le contexte). **[à relire]**
- **Droits** : `policy.manage` (administrateurs d'organisation) pour les règles ; la liste
  des violations est ouverte à tout membre, filtrée par équipe (projet du constat, équipe
  de l'agent ; un agent d'organisation n'est vu que des administrateurs). **[à relire]**
- **Tableau de bord** (renvoi d'ADR 0027) : section « Alertes » (violations ouvertes,
  bloquantes, cinq plus récentes). Les « objectifs de délai par sévérité » ne deviennent pas
  un réglage à part : un objectif se dit par une règle (le modèle « critique avec correctif
  depuis plus de 30 jours » en est un) et ses violations paraissent dans la section.
  **[à relire]**

## Conséquences

- Une règle qui compile aujourd'hui peut échouer sur une donnée (étiquette absente lue par
  `project.labels["env"]`) : l'écran l'affiche ; `has(project.labels.env)` l'évite.
- Le verdict d'un commit dépend de l'état courant de la référence : les violations sont
  rattachées aux constats, qui sont par référence, pas par instantané.
- L'aperçu évalue la règle sur tous les constats ouverts de l'organisation, à la demande :
  son coût croît avec le parc ; il n'est pas encore mesuré sur le jeu de référence (à faire
  avec la recette du lot 2, T18).

## Alternatives écartées

- **`github.com/google/cel-go` v0.31.0** : chemin validé mot pour mot, mais figé ; toute
  montée de version imposerait le changement de chemin. Même projet, même licence.
- **Variables en tables dynamiques (`map(string, dyn)`)** : plus simple, mais un champ mal
  orthographié ne serait vu qu'à l'exécution, en silence.
- **Évaluation en SQL** (traduire CEL en requêtes) : rapide sur de gros volumes, mais un
  traducteur maison et un sous-ensemble du langage.
- **Violation rattachée à l'instantané** : verdict exact pour un commit ancien, mais
  autant de violations que d'instantanés et aucune résolution naturelle.
