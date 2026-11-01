# 0051 — Corrections de la revue de sécurité du lot 2

- Statut : Accepté
- Date : 2026-11-01
- Lot : T18
- Modifie : [0048](0048-codes-de-secours.md) (reconfiguration du second facteur),
  [0014](0014-jetons-et-api-des-agents.md) (rattachement par le nom d'hôte)

## Contexte

La revue de sécurité indépendante du lot 2 (T18, OWASP Risk Rating, journal de T18
« Revue de sécurité ») a relevé 0 Critical, 0 High, 2 Medium, 5 Low et 3 Note, sans fuite
entre organisations. Plusieurs correctifs changent un comportement visible ou une décision
d'un ADR antérieur ; ils sont consignés ici. Toutes ces décisions ont été prises sans
validation explicite de l'utilisateur (lot 2 enchaîné en autonomie).

## Décision

1. **Enrôlement du TOTP (SEC2-01)** : open-go-base v1.4.1 (PR #6, commit `0900e0c`) :
   `EnablePOST` ne fait rien sur un TOTP actif (redirection, code non examiné) et compte
   chaque code faux dans le verrouillage par compte. lotor garde en plus, en défense en
   profondeur, une enveloppe de la route `POST /account/totp/enable` qui renvoie vers
   `/account/security` quand le TOTP est actif. Les échecs d'enrôlement ne sont pas
   journalisés un par un : sur un TOTP inactif, le détenteur de la session voit déjà le
   secret (aucune force brute utile), et le verrouillage est journalisé
   (`account.locked`). **[à relire]**
2. **Reconfiguration par le titulaire (SEC2-06)** : elle exige désormais un **nouveau mot de
   passe** (avec confirmation), validé avant la consommation du code de réauthentification,
   et posé dans la même transaction que le retrait du TOTP ; sessions fermées, jetons
   personnels gardés. L'ancien mot de passe, peut-être dérobé (hameçonnage arrêté jusque-là
   par le TOTP), ne permet plus d'enrôler un second facteur avant la reconnexion du
   titulaire. Écarté : enchaîner l'enrôlement dans la session courante (l'ancien mot de
   passe ouvrirait encore une session de configuration concurrente, qui écraserait le
   secret en cours) ; mot de passe temporaire imposé (le titulaire n'a rien à recevoir
   d'un administrateur). Modifie la décision « mot de passe et jetons gardés » de l'ADR
   0048. **[à relire]**
3. **Inscription par le nom d'hôte (SEC2-02)** : sans projet désigné, un jeton d'inscription
   ne rattache que le projet hôte **de son équipe** ; un homonyme d'une autre équipe répond
   « hôte déjà suivi » (`error.enrollment.host_taken`), qu'il ait un agent, aucun, ou qu'il
   soit archivé, sans révéler son équipe (la référence d'hôte reste unique dans
   l'organisation : l'administrateur d'organisation lève le conflit). Un projet désigné
   passé dans une autre équipe depuis la création du jeton n'est plus confié
   (`project_unavailable`). Le rattachement par le nom aux projets libérés par une
   désactivation reste permis dans l'équipe (SEC-13, hypothèse « hôtes non compromis à
   l'inscription »). **[à relire]**
4. **Dépôt changé, IA externe retirée (SEC2-03)** : l'autorisation d'un fournisseur externe
   vaut pour un dépôt ; changer l'URL de forge d'un projet « externe » ramène le réglage à
   **« désactivé »** (pas « local » : aucun modèle n'est appelé tant qu'un administrateur ne
   l'a pas décidé), journalisé (`project.ai_mode_changed`, motif `forge_url_changed`), sauf
   si l'acteur a lui-même le droit `ai.external` (et que l'instance ne l'interdit pas).
   **[à relire]**
5. **Secrets des canaux (SEC2-04)** : un secret laissé vide est gardé, sauf si la
   destination à laquelle il part change (serveur Matrix, URL du webhook générique) : il
   faut alors le ressaisir (`KeySecretRequired`) ; le changement de destination est
   journalisé. Le salon Matrix peut changer sans ressaisie (même serveur). **[à relire]**
6. **Conteneurs par hôte (SEC2-05)** : `containers.max_per_host` (1 000 par défaut, 1 à
   100 000) borne les projets enfants d'un hôte, actifs ou archivés ; un signalement qui en
   créerait davantage est **refusé en entier** (409, `error.agent.containers_limit`), sans
   rien créer. Pas de quota quotidien : seule la purge (`containers.purge_after`, 180 jours)
   supprime un enfant, la borne totale borne donc aussi les créations dans le temps.
   Écarté : créer jusqu'à la borne et ignorer le reste (réponse de l'API avec des projets
   sans identifiant). **[à relire]**
7. **Fichiers exclus et fournisseur de modèle (SEC2-07)** : le périmètre incrémental (fichiers
   modifiés selon la forge) est filtré par les exclusions et la détection de clé privée
   avant le prompt ; `list_dir` ne liste plus un fichier de **64 Kio au plus** qui contient
   une clé privée. Un fichier plus gros qui en contiendrait une reste listé puis refusé à
   la lecture (« not found ») : reste accepté, pour borner le coût d'une liste
   (500 entrées × 64 Kio au plus). **[à relire]**
8. **Garde SSRF (SEC2-08)** : plages réservées refusées, adresses NAT64 (`64:ff9b::/96`),
   6to4 (`2002::/16`) et IPv4-compatibles jugées sur l'IPv4 qu'elles portent, NAT64 d'usage
   local, site-local et Teredo refusés. Les **ports ne sont pas restreints** : une liste
   fermée gênerait des webhooks internes légitimes sur port explicite ; l'oracle de
   balayage de ports publics par le test d'un canal est réservé aux administrateurs
   d'organisation, audité (`channel.tested`) : risque accepté. **[à relire]**
9. **Outil `search` de l'IA (SEC2-09)** : délai vérifié entre deux fichiers et entre deux
   appels d'outils ; 2 Kio décomptés du budget de lecture par recherche ; 20 appels
   d'outils exécutés au plus par réponse du modèle (`llm.Budget.MaxCallsPerTurn`), les
   suivants reçoivent une erreur. **[à relire]**
10. **`lotor_user_invitations` sans garde SQL (SEC2-10)** : accepté, comme
    `lotor_list_organizations` (SEC-12) : l'application ne l'appelle qu'avec l'identifiant
    de la session, l'acceptation revérifie tout sous la RLS, et la fonction ne renvoie que
    des métadonnées (organisation, rôle) ; lier l'appel à un réglage de transaction
    exigerait une migration et un mécanisme nouveau pour une injection SQL qui n'existe
    pas (requêtes paramétrées, ADR 0004). **[à relire]**

## Conséquences

- Aucun chemin ne délivre de codes de secours sans un code TOTP compté dans le
  verrouillage ; aucun état intermédiaire où l'ancien mot de passe seul enrôle un second
  facteur.
- La frontière d'équipe tient aussi pour l'inscription des agents serveur.
- Les réglages de sécurité qui suivent une ressource (IA externe, secret d'un canal) ne
  suivent pas un changement de cette ressource.
- Nouveau réglage `containers.max_per_host` ; un hôte très chargé en conteneurs
  éphémères nommés au hasard doit relever la borne ou nommer ses conteneurs.
- Formulaire de reconfiguration du second facteur plus long (deux champs de mot de passe).

## Alternatives écartées

Voir chaque point ci-dessus.
