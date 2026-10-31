# Grille RGAA 4.1 — écrans du lot 1

Recette T11, critère « Grille RGAA remplie pour chaque écran, sans non-conformité
bloquante ». Grille **finale**, après corrections : audit initial le 31 octobre 2026 sur
`main` (8369ad0), contre-audit le même jour sur la branche `lot/T11-accessibilite`
(corrections du commit 9bd0e4a, en plus de celles de la partie 1 de T11, PR #13).

## 1. Synthèse

| Indicateur | Audit initial | Après corrections |
|---|---|---|
| Critères RGAA 4.1 | 106 | 106 |
| Applicables (au moins un écran) | 70 | 72 |
| Conformes | 60 | 72 |
| Non conformes | 10 | 0 |
| Non applicables | 36 | 34 |
| **Taux de conformité** | **85,7 %** | **100 %** |
| Constats (NC) | 13 : 0 bloquante, 4 majeures, 9 mineures | 0 ouvert |

Taux au sens du RGAA : un critère est non conforme dès qu'il échoue sur un écran de
l'échantillon. Les critères 12.3 et 12.4 (plan du site) deviennent applicables avec le
plan du site ajouté pour NC-13, d'où 72 critères applicables. Ce taux vaut dans les
limites du § 7 (pas de lecteur d'écran réel, Chromium seul).

### Constats et statut

| Id | Gravité | Critères | Constat | Correction | Statut |
|---|---|---|---|---|---|
| NC-01 | majeure | 10.11 | navigation latérale plus large que l'écran sous 64rem | `min-width: 0` sur `.sidenav` | corrigé (PR #13), vérifié |
| NC-02 | majeure | 10.11, 10.4 | texte masqué hors des tableaux défilants | `position: relative` sur `.table-wrap` | corrigé (PR #13), vérifié |
| — | défaut | 10.11 | bande vide sous la navigation en mobile | `align-content: flex-start` sous 64rem | corrigé (PR #13), vérifié |
| NC-03 | mineure | 10.11 | menu du sélecteur d'organisation hors écran à 320 px | menu à la largeur de l'en-tête sous 30rem | corrigé 9bd0e4a |
| NC-04 | mineure | 10.11 | PURL insécable dans l'en-tête de la fiche composant | `overflow-wrap: anywhere` | corrigé 9bd0e4a |
| NC-05 | majeure | 3.1, 10.9, 10.10 | compteurs de sévérité sans libellé visible | abréviation écrite (« Crit. 1 »), libellé complet pour les lecteurs d'écran, `title` au survol | corrigé 9bd0e4a |
| NC-06 | mineure | 3.1 | ligne sélectionnée signalée par le seul fond | filet et graisse en première cellule ; « Affichée », « Version de cette fiche » écrits | corrigé 9bd0e4a |
| NC-07 | mineure | 3.1 | version vulnérable signalée par la couleur de la barre | « Version vulnérable » écrit dans la ligne | corrigé 9bd0e4a |
| NC-08 | mineure | 8.6 | titres identiques d'une organisation à l'autre, recherche, formulaire en erreur | titre « écran — organisation », requête de recherche, préfixe « Erreur : » | corrigé 9bd0e4a |
| NC-09 | mineure | 8.7 | « English » sans `lang="en"` | `lang` sur les options de langue et la colonne langue des organisations | corrigé 9bd0e4a |
| NC-10 | mineure | 11.9 | bouton « Modifier » sans contexte | « Modifier le rôle » + e-mail masqué ; boutons de la colonne de nouveau visibles | corrigé 9bd0e4a |
| NC-11 | mineure | 11.10 | format « clé ou clé=valeur » réservé aux lecteurs d'écran | aide visible | corrigé 9bd0e4a |
| NC-12 | majeure | 11.12 | actions irréversibles en un clic | page de confirmation commune (§ 5) | corrigé 9bd0e4a |
| NC-13 | mineure | 12.1 | un seul système de navigation | plan du site `/sitemap`, lié du pied de page | corrigé 9bd0e4a |

Aucune non-conformité bloquante, ni avant ni après corrections.

## 2. Méthode et échantillon

- **Instance** : test d'intégration jetable (non commité) qui peuple une base
  PostgreSQL éphémère puis sert l'application : organisation `acme` (deux dépôts dont un
  ingéré deux fois, un serveur), organisation `beta` vide, SBOM réels de test, base de
  vulnérabilités factice (critique KEV, élevée, moyenne, inconnue), constats ouverts et
  résolus, agent dépôt et ses jetons, jeton d'inscription, jeton personnel, statistiques,
  deux traitements en échec, deux archives de la base et deux instances worker, compte
  administrateur, lecteur et compte neuf.
- **Échantillon** : 88 pages découvertes en suivant tous les liens d'une session
  administrateur, plus les états qui demandent une action (connexion et code en erreur,
  enrôlement TOTP, formulaires en erreur, secrets affichés une fois, erreurs 403, 404,
  500, CSRF) et, au contre-audit, les 11 pages de confirmation et le plan du site. Chaque
  page en français et en anglais, en thème clair et sombre.
- **Outils** : Chromium (Playwright) ; axe-core 4.10.2 (WCAG 2.0/2.1 A et AA et bonnes
  pratiques) injecté dans chaque rendu (368 rendus au contre-audit, **aucun écart**, y
  compris la règle `landmark-unique` relevée 116 fois à l'audit initial) ; contrôles
  maison (langue, titres, zones, identifiants, tableaux, SVG, liens génériques) ;
  parcours au clavier de chaque page (ordre, focus visible, pièges) ; redistribution à
  320 × 640 et 390 × 844 et texte à 200 % à 1 280 px (aucun défilement horizontal sur
  les 88 pages et les confirmations) ; espacement du texte (WCAG 1.4.12) ; contrastes
  recalculés depuis `tokens.css` ; captures de contrôle en clair et en sombre des écrans
  corrigés ; lecture de tous les gabarits et des CSS.
- **Barrières automatiques** (`make test-integration`) : `webtest.CheckAccessibility` sur
  chaque écran (dont désormais : aide `aria-describedby` jamais masquée visuellement, nom
  de langue d'un choix de langue marqué de sa langue), `TestEveryScreenIsAccessible`,
  `TestIrreversibleActionsAreConfirmed`, `TestPageTitlesAreDistinct`, `TestSiteMap`,
  `TestRenderTitle`.
- **Gravité** : *bloquante* = tâche impossible pour un profil ; *majeure* = tâche
  réalisable au prix d'un effort important ou information essentielle inaccessible à un
  profil ; *mineure* = gêne ponctuelle ou information redondante ailleurs.

## 3. Grille du gabarit commun (106 critères)

Statut agrégé sur tout l'échantillon après corrections (C conforme, NA non applicable).

| Thématique | Critères | Statut | Justification |
|---|---|---|---|
| 1 Images | 1.1, 1.2, 1.3, 1.6, 1.7 | C | QR code du TOTP avec `alt` traduit et clé en clair ; icônes SVG `aria-hidden` ; graphiques `role="img"` nommés et décrits, tableau des valeurs |
| | 1.4, 1.5, 1.8, 1.9 | NA | ni CAPTCHA, ni image texte, ni `figure` |
| 2 Cadres | 2.1, 2.2 | NA | aucun cadre |
| 3 Couleurs | 3.1 | C | sévérités écrites partout (badges, compteurs abrégés), ligne sélectionnée écrite et marquée par un filet, version vulnérable écrite, états en texte |
| | 3.2, 3.3 | C | aucun défaut de contraste (axe, 368 rendus ; jetons recalculés) |
| 4 Multimédia | 4.1 à 4.13 | NA | aucun média temporel |
| 5 Tableaux | 5.4 à 5.7 | C | `caption` ou panneau nommé, `th scope` partout |
| | 5.1 à 5.3, 5.8 | NA | ni tableau complexe ni tableau de mise en forme |
| 6 Liens | 6.1, 6.2 | C | contexte suffisant, intitulés complétés de texte masqué (« Révoquer initial », « Retirer a@b ») |
| 7 Scripts | 7.1 à 7.5 | C | seul script : bascule de thème (bouton natif) ; aucune soumission automatique ; messages après rechargement en `role="status"` / `role="alert"` ; confirmations sans JavaScript |
| 8 Éléments obligatoires | 8.1 à 8.5, 8.8, 8.9 | C | doctype, code analysé sans erreur, `lang` juste sur les 368 rendus, titre présent |
| | 8.6 | C | titre « écran — organisation », requête de recherche, « Erreur : » sur un formulaire refusé, objet nommé sur les confirmations |
| | 8.7 | C | `lang` sur « English » / « Français » et sur le résumé anglais d'une vulnérabilité |
| | 8.10 | NA | |
| 9 Structuration | 9.1 à 9.3 | C | un `h1`, aucun saut ; `header`, `nav` nommée, `main`, `footer` ; listes structurées |
| | 9.4 | NA | |
| 10 Présentation | 10.1 à 10.8, 10.12, 10.13 | C | aucun style en ligne ; contenu lisible sans CSS ; texte à 200 % sans perte ; focus visible ; espacements redéfinissables |
| | 10.9, 10.10 | C | sévérité jamais portée par la seule forme du repère : libellé écrit |
| | 10.11 | C | aucun défilement horizontal de page à 320 px (88 pages et confirmations) ; seules les zones de tableau défilent, focalisables et nommées |
| | 10.14 | NA | |
| 11 Formulaires | 11.1 à 11.7, 11.11, 11.13 | C | `label` partout, `fieldset` / `legend`, suggestions de correction, `autocomplete` |
| | 11.9 | C | « Modifier le rôle » + e-mail, boutons et liens d'action complétés de l'objet |
| | 11.10 | C | champs obligatoires `required`, aides visibles et liées (`aria-describedby`), erreurs nommant le champ |
| | 11.12 | C | actions irréversibles confirmées (§ 5) ; purge des archives par case de confirmation vérifiée côté serveur ; archivages et désactivation de compte réversibles |
| | 11.8 | NA | |
| 12 Navigation | 12.1 | C | navigation latérale et plan du site |
| | 12.2 | C | navigation et pied de page à la même place sur chaque page |
| | 12.3 | C | plan du site : toutes les rubriques ouvertes au compte (organisations selon le rôle, compte, administration) |
| | 12.4 | C | lien « Plan du site » au même endroit du pied de chaque page authentifiée |
| | 12.5 | C | « Recherche » à la même place dans chaque organisation |
| | 12.6 à 12.9, 12.11 | C | zones nommées, lien d'évitement, ordre de tabulation, aucun piège |
| | 12.10 | NA | aucun raccourci |
| 13 Consultation | 13.1, 13.2, 13.5, 13.6, 13.9, 13.11 | C | session glissante, délai TOTP (exception de sécurité), aucune nouvelle fenêtre, vecteur CVSS décodé |
| | 13.3, 13.4, 13.7, 13.8, 13.10, 13.12 | NA | téléchargements de données, aucune animation |

## 4. Grille par écran

Tous les écrans sont conformes après corrections. Colonne « Corrigé » : constats levés
sur l'écran ; « Tableaux » et « Formulaire » : état des thématiques 5 et 11 sur l'écran.

| Écran | URL | Corrigé | Tableaux | Formulaire |
|---|---|---|---|---|
| Connexion (vierge, erreur) | `/login` | — | NA | C |
| Saisie du code TOTP | `/login/2fa` | — | NA | C |
| Enrôlement TOTP | `/account/totp/setup` | — | NA | C |
| Changement de mot de passe | `/account/password` | NC-01 | NA | C |
| Profil | `/account` | NC-01, NC-09 | NA | C |
| Jetons d'accès personnels | `/account/tokens` | NC-01, NC-02, NC-12 | C | C |
| Confirmation : révoquer un jeton personnel | `/account/tokens/{id}/revoke` | nouvel écran | NA | C |
| Plan du site | `/sitemap` | nouvel écran (NC-13) | NA | NA |
| Administration — comptes | `/admin/users` | NC-01 | C | C |
| Administration — fiche compte | `/admin/users/{id}` | NC-01, NC-12 | NA | C |
| Confirmation : réinitialiser mot de passe ou TOTP | `/admin/users/{id}/reset-password`, `…/reset-totp` | nouvel écran | NA | C |
| Administration — organisations, fiche | `/admin/orgs`, `/admin/orgs/{slug}` | NC-01, NC-09 | C | C |
| Administration — base de vulnérabilités (cible, vérification, instances, import, imports récents, archives, purge) | `/admin/vulndb` | NC-01, aide de l'import liée au champ | C | C |
| Administration — traitements en échec | `/admin/jobs` | NC-01, NC-12 (abandon) | C | C |
| Confirmation : abandonner un traitement | `/admin/jobs/{id}/discard` | nouvel écran | NA | C |
| Journaux d'audit (instance, organisation) | `/admin/audit`, `/o/{slug}/audit` | NC-01, NC-03, NC-08 | C | NA |
| Tableau de bord d'organisation | `/o/{slug}` | NC-01 à NC-03, NC-05 | C | C |
| Projets — liste et filtres | `/o/{slug}/projects` | NC-01, NC-03, NC-08, NC-11 | C | C |
| Projet — création | `/o/{slug}/projects/new` | NC-01, NC-03, NC-08 | NA | C |
| Projet — vue d'ensemble, paramètres | `/o/{slug}/projects/{p}`, `…/settings` | NC-01, NC-03 | C | C |
| Projet — constats | `/o/{slug}/projects/{p}/findings` | NC-01, NC-03, NC-05, NC-06 | C | C |
| Projet — instantanés, détail | `…/snapshots`, `…/snapshots/{id}` | NC-01, NC-03, NC-06 | C | C |
| Fiche vulnérabilité | `/o/{slug}/vulnerabilities/{id}` | NC-01, NC-03 | C | NA |
| Fiche composant | `/o/{slug}/components/{id}` | NC-01, NC-03, NC-04, NC-06, NC-07 | C | NA |
| Recherche (vide, résultats, filtres) | `/o/{slug}/search` | NC-01 à NC-03, NC-08 | C | C |
| Agents — liste, jetons d'inscription | `/o/{slug}/agents` | NC-01 à NC-03, NC-08, NC-12 | C | C |
| Agent — fiche | `/o/{slug}/agents/{id}` | NC-01 à NC-03, NC-12 | C | C |
| Confirmation : révoquer un jeton d'agent, désactiver un agent | `…/agents/{id}/tokens/{t}/revoke`, `…/agents/{id}/disable` | nouvel écran | NA | C |
| Nouvel agent dépôt, jeton affiché | `/o/{slug}/agents/new` | NC-01, NC-03, NC-08 | NA | C |
| Inscription de serveurs et assistant | `/o/{slug}/enrollment-tokens/new` | NC-01, NC-03, NC-08 | NA | C |
| Confirmation : révoquer un jeton d'inscription | `/o/{slug}/enrollment-tokens/{t}/revoke` | nouvel écran | NA | C |
| Membres (liste, ajout, erreur) | `/o/{slug}/members` | NC-01 à NC-03, NC-08, NC-10, NC-12 | C | C |
| Confirmation : retirer un membre (soi-même compris) | `/o/{slug}/members/{id}/remove` | nouvel écran | NA | C |
| Paramètres d'organisation | `/o/{slug}/settings` | NC-01, NC-03, NC-08, NC-09 | NA | C |
| Erreurs 403, 404, 500, CSRF | | — | NA | NA |

### Écrans d'administration ajoutés par la partie 1 de T11

- **`/admin/jobs`** : compteurs en liste (`ul.stat-grid`) avec libellé écrit ; tableau des
  jobs morts en `th scope`, zone défilante nommée par le titre du panneau ; « Relancer »
  (réversible) agit en un clic, « Abandonner » (supprime le job et son erreur) passe par
  la confirmation ; intitulés complétés du type de job ; message « déjà relancé ou
  abandonné » en `role="alert"` ; à 320 px aucun débordement.
- **`/admin/vulndb`** : listes de définitions (`dl.kv`) ; états des instances et des
  imports écrits (« À jour », « En retard sur la cible », « Sans nouvelles », jamais la
  seule couleur) ; formulaire d'import avec libellé, aide de taille maximale liée au champ
  (corrigé), erreur nommant le champ, état « import en cours » écrit à la place du
  formulaire ; archive cible écrite (« Cible ») et marquée comme ligne sélectionnée ;
  purge confirmée par une case obligatoire vérifiée côté serveur (422 sinon). Le texte du
  champ de fichier natif (« Choose File ») suit la langue du navigateur, pas celle de la
  page : contrôle natif, hors du contenu.

## 5. Confirmation des actions irréversibles (NC-12)

Mécanisme unique, sans JavaScript : l'écran qui propose l'action n'a qu'un lien vers
l'URL de l'action ; un `GET` sur cette URL rend la page commune `confirm/action` (titre
en question nommant l'objet, encadré « Cette action est définitive » avec les
conséquences, bouton qui nomme l'action et l'objet, lien « Annuler » vers l'écran
d'origine) ; son formulaire `POST` vers la même URL agit, avec le jeton CSRF. Le `GET`
ne modifie rien, répond 404 pour un objet absent ou d'une autre organisation (harnais
d'isolement par route) et renvoie à l'écran si l'objet est déjà révoqué ou désactivé.
Couvre : jeton d'agent, jeton d'inscription, jeton personnel, désactivation d'un agent,
retrait d'un membre (avertissement propre quand on se retire soi-même), réinitialisation
du mot de passe et du TOTP d'un compte, abandon d'un traitement en échec.

Restent en un clic, parce que réversibles : archiver ou désarchiver un projet ou une
organisation, désactiver ou réactiver un compte, nommer ou retirer un administrateur,
relancer un traitement. La purge des archives de la base garde sa case de confirmation
(partie 1 de T11), conforme elle aussi.

## 6. Recommandations hors grille restantes

Traitées avec les corrections : R-01 (régions de tableau homonymes de leur panneau, en
groupes), R-05 (espaces entre texte masqué et visible), R-06 (toutes les zones de tableau
focalisables et nommées), R-11 (couleur des textes indicatifs par jeton).

Ouvertes, sans effet sur la conformité :

- **R-02** relier le message d'erreur d'un formulaire au champ en `aria-invalid`
  (`aria-describedby` vers l'encadré) ;
- **R-03** mention visible des champs obligatoires ;
- **R-04** `aria-live` inutile sur la zone de résultats de la recherche ;
- **R-07** pictogramme « Dépôt » proche d'une case à cocher ;
- **R-08** bascule de thème : annoncer l'action, pas seulement l'état ;
- **R-09** langue perdue après un POST public ou une redirection (`?lang=`) ;
- **R-10** enrôlement TOTP : un code faux régénère la clé.

## 7. Limites de l'audit

- Pas de test avec un lecteur d'écran réel (NVDA, JAWS, VoiceOver, TalkBack) : la
  restitution est jugée sur l'arbre d'accessibilité de Chromium et sur le code.
- Chromium seul ; ni Firefox ni Safari (Safari ne rend pas focalisable une zone
  défilante sans `tabindex` : toutes en ont désormais un).
- Validité du code (8.2) : analyse locale ; le validateur du W3C n'a pas été appelé
  (envoi de pages à un service tiers).
- Zoom à 200 % simulé par la taille de police racine à 1 280 px ; redistribution mesurée
  à 320 et 390 px.
- Audit réalisé par l'équipe qui a écrit l'interface, outillé ; un audit par un tiers
  certifié reste à faire avant toute déclaration de conformité publique.
