# Grille RGAA 4.1 — écrans du lot 2

Recette T18 (partie 3), critère « Grille RGAA remplie pour chaque nouvel écran, sans
non-conformité bloquante ». Grille **finale**, après corrections : audit initial le
1er novembre 2026 sur `main` (f53536f, tout le lot 2 et la partie 1 de T18), contre-audit
le même jour sur la branche `lot/T18-accessibilite`. Modèle et conventions : grille du
lot 1 ([`grille-rgaa-lot1.md`](grille-rgaa-lot1.md)) et § 14 de l'architecture.

## 1. Synthèse

| Indicateur | Audit initial | Après corrections |
|---|---|---|
| Critères RGAA 4.1 | 106 | 106 |
| Applicables (au moins un écran) | 72 | 72 |
| Conformes | 67 | 72 |
| Non conformes | 5 | 0 |
| Non applicables | 34 | 34 |
| **Taux de conformité** | **93,1 %** | **100 %** |
| Constats (NC) | 4 : 0 bloquante, 0 majeure, 4 mineures | 0 ouvert |

Taux au sens du RGAA : un critère est non conforme dès qu'il échoue sur un écran de
l'échantillon. Les critères non conformes à l'audit initial sont 8.2, 8.6, 8.7, 10.11 et
11.2. Le gabarit commun, déjà audité au lot 1, n'a pas régressé (axe-core sans écart sur
les 724 rendus, mêmes contrôles). Ce taux vaut dans les limites du § 7.

### Constats et statut

| Id | Gravité | Critères | Constat | Correction | Statut |
|---|---|---|---|---|---|
| NC-01 | mineure | 8.2, 11.2 | panneau de triage : la justification VEX, la date d'échéance et la plage `vers` sont des champs étiquetés **à l'intérieur** de l'étiquette du bouton radio (`<label>` dans `<label>`, code invalide) ; le nom du radio coché « Risque accepté » englobait l'étiquette et l'aide de la date | champs complémentaires sortis de l'étiquette, dans l'élément de liste (`li.choice-item`), révélés par `:has()` comme avant ; `webtest` refuse une étiquette imbriquée ou à plusieurs champs | corrigé, vérifié |
| NC-02 | mineure | 10.11 | fiche composant : la répartition des versions déborde de 12 px à 320 px avec une version longue de paquet de distribution (`1.36.1-r29`, conteneurs Alpine) — écran du lot 1, révélé par les données du lot 2 | le décompte passe à la ligne, barre réduite à 3 rem sous 30 rem | corrigé, vérifié |
| NC-03 | mineure | 8.6 | fiche d'un constat : même titre pour la même vulnérabilité sur le même composant de deux projets (deux conteneurs d'une même image, par exemple) | titre « CVE sur composant — projet (référence) — organisation » | corrigé, vérifié |
| NC-04 | mineure | 8.6, 8.7 | confirmation du retrait d'une décision de triage : statut écrit par sa valeur VEX (« Retirer la décision « not_affected » ? ») dans le titre, le titre de page et le bouton, en anglais technique sur une page française | libellé traduit du statut (« Non affecté », “Not affected”) | corrigé, vérifié |
| — | défaut | — | « 1 projets actifs » (fiche d'équipe), « État : Ouverts » (fiche d'un constat), « 1 ouvertes · 1 bloquantes » (alertes du tableau de bord) | décomptes au pluriel juste (`Tn`), « Ouvert » / « Résolu », « Ouvertes : 1 · bloquantes : 1 » | corrigé, vérifié |

Aucune non-conformité bloquante ni majeure, ni avant ni après corrections.

## 2. Méthode et échantillon

- **Instance** : test d'intégration jetable (étiquette `rgaaserve`, hors dépôt) qui peuple
  une base PostgreSQL éphémère sur le PostgreSQL local puis sert l'application réelle
  (routeur complet, CSS embarquées) sur un port fixe ; Playwright y navigue avec les
  cookies de session de chaque compte. Données : organisation `acme` avec trois équipes
  (Général, Plateforme, Mobile), un administrateur d'instance, un analyste, un lecteur, un
  administrateur d'équipe, un invité (`bob`, sans organisation, deux invitations en
  attente) ; trois dépôts (comparaison de deux instantanés avec montée de version de
  `log4j-core`, dépôt de l'équipe Plateforme avec décision « risque accepté » à échéance et
  décision d'organisation « non affecté », dépôt enrichi par l'IA avec preuve) ; un vrai
  `lotor-host-agent` qui inventorie un hôte et trois conteneurs (Docker simulé, deux
  répliques) ; base de vulnérabilités factice (critique KEV, élevée, faible) ; canal
  webhook et canal e-mail, politique « KEV en production » bloquante, violations, alertes
  du tableau de bord, statistiques ; codes de secours générés ; compte neuf enrôlé.
  Organisation `beta` vide (états vides de chaque écran).
- **Échantillon** : 179 pages découvertes en suivant tous les liens de cinq sessions
  (administrateur, analyste, lecteur, administrateur d'équipe, invité), ramenées à deux
  pages par forme d'URL (158 pages), plus 23 états choisis (filtres de la recherche par
  équipe, conteneurs et statut de triage, filtre refusé, comparaison filtrée, inversée et
  sans précédent, constats masqués affichés, fiche composant avec preuve IA, origine IA,
  violations résolues, fiche d'un constat vue par un lecteur et un analyste, codes de
  secours montrés une fois après la régénération et après l'enrôlement, connexion après
  reconfiguration, page du second facteur d'un compte sans code, accueil d'un invité).
  Chaque page en français et en anglais, thème clair et sombre : **724 rendus**. Plus
  16 états obtenus en soumettant réellement les formulaires dans le navigateur, en deux
  langues : 13 erreurs (nom d'équipe pris, membre absent, règle CEL invalide, nom vide,
  URL de webhook invalide, destinataires manquants, code TOTP faux à la régénération et à
  la reconfiguration, VEX illisible pour le projet et pour l'organisation, invitation
  invalide, filtre de triage refusé, code de secours faux à la connexion), l'aperçu d'une
  règle, l'essai d'un canal et une décision de triage.
- **Outils** : Chromium (Playwright) ; axe-core 4.10.2 (WCAG 2.0/2.1 A et AA et bonnes
  pratiques) injecté dans chaque rendu ; contrôles maison (un `h1`, ordre des titres,
  identifiants uniques, liens et boutons nommés, liens génériques, SVG, titres et `scope`
  des tableaux, étiquettes et références `aria-describedby`, styles en ligne) ; arbre
  d'accessibilité de Chromium (CDP) pour les noms des champs du panneau de triage ;
  parcours au clavier (ordre, focus visible, pièges) des écrans nouveaux dans les deux
  thèmes ; redistribution à 320 et 390 px et texte à 200 % à 1 280 px sur toutes les pages
  (défilement horizontal de la page et éléments qui dépassent hors zones défilantes) ;
  doublons de titres de page ; recherche de valeurs techniques non traduites dans le texte
  visible ; captures de contrôle (1 280 px clair et sombre, 390 px) ; lecture de tous les
  gabarits et CSS ajoutés par le lot 2.
- **Barrières automatiques** (`make test-integration`) : `webtest.CheckAccessibility` sur
  chaque écran (désormais aussi : étiquette sans étiquette imbriquée ni second champ),
  `TestTriageScreens` (titre de la fiche d'un constat, état au singulier, statut traduit
  sur la confirmation de retrait), `TestTeamScreens` (décomptes), `TestPolicyScreens`
  (alertes du tableau de bord), et les balayages existants.
- **Gravité** : *bloquante* = tâche impossible pour un profil ; *majeure* = tâche
  réalisable au prix d'un effort important ou information essentielle inaccessible à un
  profil ; *mineure* = gêne ponctuelle ou information redondante ailleurs.

## 3. Grille des écrans du lot 2 (106 critères)

Statut agrégé sur tout l'échantillon après corrections (C conforme, NA non applicable).

| Thématique | Critères | Statut | Justification |
|---|---|---|---|
| 1 Images | 1.1, 1.2, 1.3, 1.6, 1.7 | C | icônes et repères `aria-hidden` ; échelle de confiance de la preuve IA `aria-hidden`, doublée du libellé (« Confiance élevée ») et de la valeur ; graphiques du tableau de bord inchangés (`role="img"`, tableau des valeurs) ; QR code de l'enrôlement inchangé |
| | 1.4, 1.5, 1.8, 1.9 | NA | ni CAPTCHA, ni image texte, ni `figure` |
| 2 Cadres | 2.1, 2.2 | NA | aucun cadre |
| 3 Couleurs | 3.1 | C | statut de triage écrit et marqué par la forme de son repère ; nature d'un changement écrite (le repère + − ↑ ↓ et sa couleur ne font que la souligner) ; origine « IA » écrite ; « Bloquante », état des conteneurs, état des canaux et des politiques écrits ; choix coché du panneau de triage signalé par le bouton radio |
| | 3.2, 3.3 | C | aucun défaut de contraste (axe, 724 rendus, clair et sombre) ; repères non textuels doublés de texte |
| 4 Multimédia | 4.1 à 4.13 | NA | aucun média temporel |
| 5 Tableaux | 5.4 à 5.7 | C | `caption` ou zone nommée ; tableaux de l'effet sur la sécurité titrés par leur `h3` (`aria-labelledby`) ; `th scope` partout ; pied de tableau des périmètres en `th scope="row"` |
| | 5.1 à 5.3, 5.8 | NA | ni tableau complexe ni tableau de mise en forme |
| 6 Liens | 6.1, 6.2 | C | intitulés complétés de texte masqué (« Retirer CVE-… purl », « Supprimer KEV en production », « Essayer Astreinte », « Décliner Org acme », « Retirer la décision « Risque accepté » ») ; ancre de la preuve depuis le nom du fichier |
| 7 Scripts | 7.1 à 7.5 | C | aucun script ajouté par le lot 2 ; champs complémentaires du triage révélés en CSS (`:has()`), masqués aussi des technologies d'assistance ; résultats après rechargement en `role="status"` / `role="alert"` (aperçu d'une règle, essai d'un canal, import VEX) |
| 8 Éléments obligatoires | 8.1, 8.3 à 8.5, 8.8, 8.9 | C | doctype, `lang` juste sur les 724 rendus, titre présent |
| | 8.2 | C | plus d'étiquette imbriquée (NC-01) ; analyse locale sans autre erreur |
| | 8.6 | C | « Erreur : » sur tout formulaire refusé (13 erreurs) ; titre des fiches de constat avec projet et référence (NC-03) ; confirmations qui nomment l'objet |
| | 8.7 | C | plus de valeur technique anglaise dans une page française (NC-04) ; noms propres et identifiants (CEL, purl, CycloneDX, OpenVEX) en `code` ou en `mono` |
| | 8.10 | NA | |
| 9 Structuration | 9.1 à 9.3 | C | un `h1`, aucun saut (preuve IA : `h2` puis `h3`, comparaison : `h2` puis `h3`) ; listes structurées (codes de secours en `ol` nommée, modèles de politiques, choix) |
| | 9.4 | NA | |
| 10 Présentation | 10.1 à 10.8, 10.12, 10.13 | C | aucun style en ligne ; focus visible partout (contour de l'élément ou de son choix, clair et sombre) ; texte à 200 % sans perte ; contenu caché (`display: none`) aussi pour les lecteurs d'écran ; statuts de triage cliquables : pastille distincte du texte voisin, soulignée au survol et au focus (10.6) |
| | 10.9, 10.10 | C | information jamais portée par la seule forme : libellé écrit |
| | 10.11 | C | aucun défilement horizontal de page à 320 et 390 px ni à 200 % (NC-02 corrigée) ; seules les zones de tableau, l'extrait de la preuve et le code des règles défilent, focalisables et nommés |
| | 10.14 | NA | |
| 11 Formulaires | 11.1, 11.3 à 11.7, 11.11, 11.13 | C | `label` partout ; `fieldset` / `legend` (statut, portée, nature du canal, sujet de la règle, canaux, réglage IA, facettes de la recherche) ; erreurs qui suggèrent la correction (position de l'erreur CEL, format attendu) ; `autocomplete="one-time-code"` sur les codes TOTP |
| | 11.2 | C | nom de chaque radio du triage limité à son statut et sa description (NC-01) |
| | 11.9 | C | « Modifier le rôle » + e-mail, boutons et liens d'action complétés de l'objet |
| | 11.10 | C | champs obligatoires `required` ; aides visibles et liées (`aria-describedby`) ; champs d'un canal selon sa nature annoncés par une aide visible ; `aria-invalid` sur le champ fautif pour les 13 erreurs |
| | 11.12 | C | suppressions (politique, canal, équipe), retraits (membre d'équipe, décision de triage), révocation et refus d'une invitation par la page de confirmation commune ; régénération des codes et changement d'application soumis à un code saisi (voir § 5) |
| | 11.8 | NA | |
| 12 Navigation | 12.1 à 12.4 | C | navigation latérale et plan du site, qui reprend les nouvelles rubriques (Équipes, Triage, Politiques, Canaux, Violations, Invitations, Second facteur) selon le rôle |
| | 12.5 | C | rubriques à la même place dans chaque organisation |
| | 12.6 à 12.9, 12.11 | C | zones nommées, lien d'évitement, ordre de tabulation, aucun piège (parcours au clavier) |
| | 12.10 | NA | aucun raccourci |
| 13 Consultation | 13.1, 13.2, 13.5, 13.6, 13.9, 13.11 | C | aucune limite de temps ajoutée (codes de secours montrés sans délai) ; aucune nouvelle fenêtre ; exports VEX en téléchargement explicite (`download`) |
| | 13.3, 13.4, 13.7, 13.8, 13.10, 13.12 | NA | exports de données (JSON), aucune animation |

## 4. Grille par écran

Tous les écrans sont conformes après corrections. Colonne « Corrigé » : constats levés
sur l'écran ; « Tableaux » et « Formulaire » : état des thématiques 5 et 11.

| Écran | URL | Corrigé | Tableaux | Formulaire |
|---|---|---|---|---|
| Connexion (après reconfiguration du second facteur) | `/login?done=totp_reconfigured` | — | NA | C |
| Second facteur, code de secours (vierge, erreur) | `/login/2fa` | — | NA | C |
| Codes de secours montrés après l'enrôlement | `POST /account/totp/enable` | — | NA | NA |
| Mon compte › Second facteur (codes restants, aucun code, codes montrés, erreurs) | `/account/security` | — | NA | C |
| Invitations reçues, confirmation du refus | `/account/invitations`, `…/{id}/decline` | — | C | C |
| Membres : invitations en attente, confirmation de révocation | `/o/{slug}/members`, `…/invitations/{id}/revoke` | — | C | C |
| Équipes (liste, création, erreur) | `/o/{slug}/teams` | — | C | C |
| Équipe (membres, rôles, renommage, erreur), confirmations de suppression et de retrait | `/o/{slug}/teams/{id}`, `…/delete`, `…/members/{u}/remove` | décomptes | C | C |
| Projet — constats (filtre et colonne de triage, constats masqués) | `…/projects/{p}/findings` | — | C | C |
| Fiche d'un constat et panneau de triage (analyste, lecteur, erreur) | `…/projects/{p}/findings/{id}` | NC-01, NC-03, état | NA | C |
| Confirmation : retirer une décision (projet, organisation) | `…/decisions/{id}/withdraw`, `/o/{slug}/triage/decisions/{id}/withdraw` | NC-04 | NA | C |
| Projet — VEX (export, import, erreur) | `…/projects/{p}/vex` | — | NA | C |
| Triage de l'organisation (décisions, import, erreur) | `/o/{slug}/triage` | — | C | C |
| Projet — instantanés (frise des changements) | `…/projects/{p}/snapshots` | — | C | C |
| Comparaison d'instantanés (filtre, inversée, sans précédent) | `…/projects/{p}/compare` | titre des tableaux d'effet | C | C |
| Instantané : origine IA, enrichissement | `…/snapshots/{id}` | — | C | C |
| Fiche composant : emplacement, preuve de la détection IA | `/o/{slug}/components/{id}` | NC-02 | C | NA |
| Projet hôte : conteneurs et constats par périmètre | `/o/{slug}/projects/{hôte}` | — | C | C |
| Projet conteneur : contexte, paramètres | `/o/{slug}/projects/{conteneur}`, `…/settings` | — | C | C |
| Projets avec les conteneurs | `/o/{slug}/projects?containers=1` | — | C | C |
| Paramètres du projet : enrichissement IA, équipe | `…/projects/{p}/settings` | — | NA | C |
| Politiques (liste, modèles), nouvelle politique (modèle, erreur CEL, aperçu), fiche, confirmation de suppression | `/o/{slug}/policies…` | — | C | C |
| Canaux (liste, essai réussi), nouveau canal (erreurs), fiche, confirmation de suppression | `/o/{slug}/channels…` | — | C | C |
| Violations (ouvertes, résolues, par politique) | `/o/{slug}/violations` | — | C | NA |
| Tableau de bord : alertes | `/o/{slug}` | décompte | C | C |
| Recherche : équipe, conteneurs, statut de triage, filtre refusé (400) | `/o/{slug}/search` | — | C | C |
| Nouvel agent, inscription de serveurs : équipe | `/o/{slug}/agents/new`, `…/enrollment-tokens/new` | — | NA | C |
| Plan du site : nouvelles rubriques | `/sitemap` | — | NA | NA |

## 5. Actions irréversibles

Les nouvelles actions irréversibles suivent la convention du § 14 de l'architecture (page
de confirmation commune, `GET` sans effet) : suppression d'une politique, d'un canal,
d'une équipe ; retrait d'un membre d'équipe et d'une décision de triage ; révocation d'une
invitation ; refus d'une invitation reçue.

Restent en un clic, parce que réversibles ou sans effet durable : accepter une invitation,
changer un rôle d'équipe, renommer une équipe, essayer un canal, rattacher un projet à une
équipe, régler l'enrichissement IA. Une décision de triage s'enregistre par le formulaire
(statut, portée, commentaire obligatoire) et se retire depuis l'historique.

**Régénérer les codes de secours** (l'ancien jeu devient caduc) et **changer
d'application d'authentification** (secret TOTP retiré, sessions fermées) n'ont pas de
page de confirmation : chacun exige la saisie d'un code (TOTP, ou code de secours pour le
changement d'application) dans un formulaire qui décrit les conséquences, le bouton du
second est marqué comme dangereux ; une erreur de saisie est signalée et corrigeable.
Ce code saisi tient lieu de confirmation au sens de 11.12 (décision de la partie 1,
ADR 0048) **[à relire]**.

## 6. Recommandations hors grille

Traitées avec les corrections : tableaux de l'effet sur la sécurité titrés par leur `h3`
(`aria-labelledby` sur la table, en plus de la zone) ; bouton « Retirer » de l'historique
d'un constat complété de la décision visée.

Ouvertes, sans effet sur la conformité (celles du lot 1 restent ouvertes, § 6 de sa
grille ; R-09, langue perdue après un `POST`, se voit aussi sur les formulaires du lot 2) :

- **R-L2-01** recherche : un filtre de triage refusé marque le champ de recherche en
  `aria-invalid`, alors que la correction est de retirer le filtre (pastille « Filtres
  actifs ») ;
- **R-L2-02** aide de la règle CEL : les valeurs à saisir (`in_triage`, `purl_base`…)
  écrites en texte courant plutôt qu'en `code` ;
- **R-L2-03** formulaire d'un canal : sans JavaScript, tous les champs de toutes les natures
  sont affichés (l'aide visible dit lesquels servent) ; une révélation par `:has()` comme au
  triage allégerait la page ;
- **R-L2-04** identifiant d'image d'un conteneur abrégé, complet seulement au survol
  (`abbr title`) sur la fiche de l'hôte ; il est écrit en entier sur la fiche du
  conteneur ;
- **R-L2-05** titre d'une fiche de constat de conteneur : la référence répète l'identité
  du conteneur (« srv-agent-01/shop/web (shop/web) »).

## 7. Limites de l'audit

- Pas de test avec un lecteur d'écran réel (NVDA, JAWS, VoiceOver, TalkBack) : la
  restitution est jugée sur l'arbre d'accessibilité de Chromium et sur le code.
- Chromium seul ; ni Firefox ni Safari. La révélation des champs du triage repose sur
  `:has()` (Chromium 105, Safari 15.4, Firefox 121) : sans lui, les champs restent masqués
  et la justification ne peut être saisie que par l'import d'un VEX.
- Validité du code (8.2) : analyse locale ; le validateur du W3C n'a pas été appelé
  (envoi de pages à un service tiers).
- Zoom à 200 % simulé par la taille de police racine à 1 280 px ; redistribution mesurée
  à 320 et 390 px.
- Données de démonstration : la forme des écrans avec des centaines de lignes (pagination)
  a été vue au lot 1 ; le lot 2 n'a pas de liste nouvelle sans pagination ni borne.
- Audit réalisé par l'équipe qui a écrit l'interface, outillé ; un audit par un tiers
  certifié reste à faire avant toute déclaration de conformité publique.
