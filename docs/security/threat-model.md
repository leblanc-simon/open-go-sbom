# Modèle de menace

Version 2 (revue de sécurité du lot 1, T11, 31 octobre 2026 ; version 1 : T00). Tenu à jour à chaque lot qui ajoute une frontière de
confiance, un actif ou un acteur (§ 19 de l'architecture). Gravité évaluée selon l'OWASP
Risk Rating au moment où une faiblesse est trouvée ; ce document liste les menaces et les
parades prévues, et le lot qui les porte. Les constats de la revue du lot 1 (SEC-01 à
SEC-14) sont rappelés entre parenthèses ; leur suivi est dans le Journal de T11.

## Actifs

| Actif | Pourquoi il compte |
| --- | --- |
| Inventaires (SBOM bruts, composants, instantanés) | Cartographie précise du parc : versions vulnérables, paquets internes, noms d'hôtes. Très utile à un attaquant. |
| Constats et décisions de triage | Liste des failles non corrigées, et de celles qu'on a jugées acceptables. |
| Comptes, mots de passe, secrets TOTP, sessions | Accès à l'interface et aux données de toutes les organisations d'un compte. |
| Jetons d'agent, d'inscription, personnels | Envoi de faux inventaires, lecture par l'API. |
| Secrets des forges (clé de GitHub App, jetons GitLab) | Lecture du code des dépôts ; détenus par l'agent dépôt seul. |
| Clés de chiffrement des secrets stockés | Déchiffrement des secrets de canaux, OIDC (lots suivants). |
| Base de vulnérabilités Grype | Une base altérée masque des vulnérabilités ou en invente. |
| Journal d'audit | Preuve des actions ; doit rester complet et non modifiable par l'application. |

## Acteurs

- **Visiteur anonyme** sur Internet, face à l'interface et aux API.
- **Membre d'une organisation** (`viewer`, `analyst`, `admin`) : légitime dans la sienne,
  hostile ou curieux envers les autres.
- **Administrateur d'instance** : rôle privilégié assumé, audité.
- **Agent compromis** : un hôte ou l'agent dépôt dont le jeton est volé.
- **Contenu hostile** : dépôt analysé, SBOM envoyé, fichier de l'hôte scanné (injection
  d'instructions pour l'IA au lot 2, bombe de décompression, JSON profond, liens
  symboliques piégés).
- **Fournisseur amont compromis** : distribution de la base Grype, dépendance Go.
- **Exploitant de la base** : accès PostgreSQL hors application.

## Frontières de confiance

1. Navigateur ↔ serveur (interface) : session, CSRF, CSP.
2. Agents ↔ serveur (API agent) : jeton d'agent, mTLS facultatif, limitation par jeton.
3. Clients ↔ serveur (API utilisateur) : jeton personnel ou session + en-tête CSRF.
4. Serveur ↔ PostgreSQL : rôle d'exécution sans contournement de la RLS.
5. Serveur ↔ distribution de la base Grype : téléchargement vérifié.
6. Agent dépôt ↔ forges : application installée en lecture seule, webhooks signés.
7. Agent dépôt ↔ contenu d'un dépôt cloné ; agent serveur ↔ système de fichiers de l'hôte.
8. Organisation A ↔ organisation B, dans le même serveur et la même base.

## Menaces et parades

### Serveur — interface web

| Menace | Parade | Lot |
| --- | --- | --- |
| Vol de session par XSS | `html/template`, CSP sans script ni style en ligne, cookies `HttpOnly`, `Secure`, `SameSite` | T01, T03 |
| Requête forgée (CSRF) | csrfx sur l'interface et l'API utilisateur par session ; jeton lié à la session (HMAC du cookie et du secret de session : écrire le cookie depuis un sous-domaine ou une réponse en clair ne suffit plus) ; protection inter-origines (`Sec-Fetch-Site`, `Origin`) avant csrfx ; cookies `__Host-` quand `auth.cookie_secure` vaut `on` (SEC-08, ADR 0031) | T03, T11 |
| Cookie de session volé et rejoué indéfiniment | session glissante (`auth.session_ttl`) bornée par une durée absolue depuis la connexion (`login.session_max_age`, 7 jours) (SEC-08) | T11 |
| Force brute du mot de passe | limitation par IP dédiée à `/login` et `/login/2fa` (une IPv6 compte pour son /64), comparaison bcrypt, journal d'audit des échecs ; pas de verrouillage sur le mot de passe (il laisserait n'importe qui verrouiller un compte par son e-mail) | T03, T11 |
| Force brute du TOTP avec un mot de passe connu | le plafond de codes par défi ne borne pas l'attaque (un nouveau défi s'obtient en rejouant le mot de passe) : verrouillage **par compte**, tous défis et réauthentifications confondus (10 codes faux en 15 min, verrouillage de 15 min doublé à chaque récidive, 24 h au plus), journalisé (`account.locked`), levé par la réinitialisation du TOTP ; IPv6 regroupée par /64 (SEC-01, ADR 0029) | T11 |
| Journal d'audit alimenté par un anonyme (échecs de connexion) | une ligne par échec, avec l'e-mail saisi ; borné par la limitation par IP (/64 en IPv6) — risque résiduel accepté (SEC-14) | T11 |
| Énumération des comptes | message d'échec unique (e-mail inconnu, mot de passe faux, compte désactivé), temps égalisé par une comparaison bcrypt factice | T03 |
| Énumération des comptes de l'instance par un administrateur d'organisation, ajout d'un compte sans son consentement | **corrigé en T16** (SEC-09, ADR 0034) : un administrateur d'organisation **invite** une adresse, avec la même réponse et le même journal que le compte existe ou non (l'invitation n'est pas liée à `users`) ; le compte ne devient membre qu'en acceptant depuis `/account/invitations` ; une invitation ne vaut que pour l'adresse invitée, une fois, 30 jours au plus, et les invitations en attente sont bornées (200 par organisation). Seul l'administrateur d'instance, qui connaît déjà les comptes, ajoute directement un membre | T11, T16 |
| Lecture des invitations d'un autre compte | la fonction `crossorg` `lotor_user_invitations` ne renvoie que les invitations adressées à l'e-mail du compte appelant (actif), d'organisations actives dont il n'est pas membre ; l'acceptation revérifie l'e-mail et l'échéance sous verrou dans `InOrg` ; tests d'intégration (autre compte, expirée, archivée, seconde acceptation) | T16 |
| Membre qui lit les projets d'une autre équipe de son organisation | filtre d'équipe déclaré à la transaction (`db.Visible`, `lotor_team_visible`) sur toutes les lectures : listes, fiches, recherche et exports, API utilisateur (jetons personnels compris), tableau de bord et statistiques, vulnérabilités, composants, agents ; échec de la requête si la visibilité n'est pas déclarée (un oubli ne montre jamais tout) ; 404 pour une ressource d'une équipe invisible ; test unique des surfaces (`TestTeamFilterOnEverySurface`) | T16 |
| Membre qui agit au-delà de son rôle d'équipe | matrice des droits unique (`internal/tenant`, `docs/security/permissions.md` généré) ; chaque route de l'organisation déclarée avec sa permission et la ressource qui porte l'équipe, garde unique ; test dérivé de la matrice sur chaque route et chaque rôle (`TestRoutePermissionsFollowMatrix`) ; un rattachement de projet exige le droit dans les deux équipes | T16 |
| Escalade par un administrateur d'équipe | il ne crée ni ne supprime d'équipe, n'invite ni ne retire de membre de l'organisation, ne touche ni aux paramètres ni au journal ; il n'ajoute à son équipe que des membres de l'organisation (clé étrangère composite) ; les agents d'organisation lui restent invisibles | T16 |
| Session ouverte sans second facteur | enrôlement obligatoire ; session authentifiée refusée sans méthode enregistrée (`session_auth`) ou sans TOTP actif | T03 |
| Réinitialisation du second facteur : le mot de passe seul ouvre l'enrôlement (premier arrivé) | réinitialiser le TOTP impose un mot de passe temporaire (montré une fois à l'administrateur) ; la procédure de secours exige `bootstrap.rescue_password` ; sessions fermées et jetons personnels révoqués (SEC-03, ADR 0029) | T11 |
| Mot de passe temporaire conservé | `must_change_pwd` impose le changement avant toute page ; affiché une seule fois, jamais dans une URL ni un journal | T03 |
| Texte arbitraire injecté par un lien (`?error=`) | seuls des codes connus sont affichés (open-go-base v1.1.0, messages `?done=` en liste fermée) | T03 |
| Usurpation de l'IP journalisée | `X-Forwarded-For` réécrit avec l'IP résolue par les seuls mandataires de confiance | T03 |
| Rejeu d'un code TOTP | mfax refuse un code déjà utilisé | T03 |
| Accès à une autre organisation (IDOR) | garde d'organisation, RLS forcée, 404 uniforme, tests d'isolement par route | T03 → |
| Clickjacking | `frame-ancestors 'none'` | T01 |
| Compte administrateur unique perdu | procédure de secours auditée, une fois par ticket ; avertissement s'il n'y a qu'un administrateur | T03 |
| Variable de secours oubliée en configuration | sans effet après application (ticket déjà journalisé), rappel à chaque démarrage | T03 |
| Administrateur d'instance qui lit une organisation | non membre : 404 ; il ne voit que les métadonnées (liste, administrateurs) et chaque réinitialisation est auditée — rôle privilégié assumé | T03 |

### Serveur — API agent et ingestion

| Menace | Parade | Lot |
| --- | --- | --- |
| Jeton d'agent volé | jeton haché (SHA-256), révocation immédiate, date de dernier usage, projets et références confiés à l'agent seuls ; jeton d'inscription borné en durée et en usages | T04 |
| Énumération ou force brute de jetons | secret de 256 bits, comparaison en temps constant, refus uniforme tant que le secret n'est pas vérifié, jetons refusés limités par IP | T04 |
| Faux inventaire pour masquer une faille | un agent n'écrit que sur ses références ; instantanés historisés et attribués ; signature au lot 3 | T04, T05, T24 |
| Déni de service par SBOM énorme ou piégé | corps multipart borné ; bornes en flux (taille reçue, taille décompressée — bombe gzip —, profondeur JSON, nombre de composants, clés comparées sans casse comme le décodeur) avant tout décodage complet ; validation par le schéma officiel avant les décodeurs tiers ; décodage dans un job (jamais dans la requête) ; son délai interrompt la lecture en flux et coupe entre les étapes, mais la validation et le décodage de Syft, linéaires en taille, vont au bout de l'étape commencée (SEC-11) ; panique d'un décodeur convertie en refus ; plafond de jobs par organisation (ADR 0015) | T05, T11 |
| Déni de service par stockage (agent compromis qui envoie des SBOM tous différents) | quota d'envois stockés par référence sur 24 h (`ingest.max_per_ref_per_day`) et de volume par organisation (`ingest.max_org_storage_mib`), 429 sans rien stocker (SEC-05, ADR 0030) ; rétention des anciens instantanés et des ensembles orphelins | T11, T17 |
| SBOM d'une autre organisation ou d'une autre référence | référence vérifiée par `project.RefForAgent` avant la lecture du SBOM puis dans la transaction qui le stocke ; composants, blobs et ensembles propres à chaque organisation (RLS, clés composites) | T05 |
| Contenu de SBOM dans les journaux ou les erreurs | seuls l'identifiant d'ingestion, la clé d'erreur et des compteurs sont journalisés ; le détail d'une violation de schéma est un pointeur JSON, jamais une valeur | T05 |
| Injection SQL | requêtes paramétrées uniquement (ADR 0004) | tous |
| Saturation de l'API par un hôte | limitation par jeton (`agent_api.rate_limit`), sans gêner les autres hôtes de la même IP | T04 |

### Serveur — recherche et API utilisateur

| Menace | Parade | Lot |
| --- | --- | --- |
| Jeton personnel volé, ou créé depuis une session volée | lecture seule, expiration obligatoire (365 jours au plus), révocation manuelle immédiate, appartenance aux organisations vérifiée à chaque requête (404 sinon), compte désactivé ou en attente (mot de passe temporaire, TOTP absent) refusé, date de dernier usage, création et révocation au journal ; **révocation d'office** à la réinitialisation du mot de passe ou du TOTP et au changement de mot de passe (case cochée par défaut) ; **création soumise à un code TOTP** (SEC-02, ADR 0029) | T09, T11 |
| Recherche qui sort de l'organisation | exécution sous la RLS ; les deux fonctions qui la contournent pour les index (nom, empreinte) lisent l'organisation dans `lotor.org_id`, jamais en paramètre, et échouent hors `InOrg` (test d'isolement) | T09 |
| Saturation par des recherches ou des exports | requête bornée (1 024 octets), composants bornés (1 000 par nom ou empreinte, 5 000 par paquet), pages bornées, exports simultanés et durée bornés (`user_api.max_exports`, `export_timeout`) avec un export à la fois par compte (SEC-07), limitation par jeton | T09, T11 |
| Saturation mémoire par le réencodage de SBOM téléchargés | réencodages simultanés bornés (`ingest.max_reencodes`), un par compte, 429 au-delà ; client parti avant le calcul ignoré (SEC-06) | T11 |
| Injection de formules dans un export CSV | cellule commençant par `=`, `+`, `-`, `@` préfixée d'une apostrophe (noms et versions viennent de SBOM non fiables) | T09 |

### Serveur — base de données

| Menace | Parade | Lot |
| --- | --- | --- |
| Requête qui oublie le filtre d'organisation | RLS forcée sur toute table d'organisation, `InOrg` seul accès, échec franc hors organisation | T01, T03 |
| Ligne qui référence une autre organisation | clés étrangères composites | T03 → |
| Rôle d'exécution trop puissant | refus de démarrer si superutilisateur, `BYPASSRLS` ou propriétaire des tables | T01 |
| Migration altérée après publication | somme SHA-256 vérifiée au démarrage | T01 |
| Fuite de secrets stockés | AES-256-GCM, clé hors base, rotation ; données associées liant chaque chiffré à sa ligne (un chiffré recopié ailleurs ne se déchiffre plus) ; secrets TOTP chiffrés (T03) | T01, T03 |
| Lecture de la base : jetons de session | jetons en clair dans `sessions` (choix d'authx) : une lecture de la base permet de reprendre une session jusqu'à son expiration ; à faire évoluer dans open-go-base (jeton haché) | ouvert |
| Journal d'audit modifié ou effacé par l'application (injection SQL, exécution de code, identifiant du rôle d'exécution volé) | `UPDATE`, `DELETE` et `TRUNCATE` retirés au rôle d'exécution sur les deux journaux, vérifiés au démarrage (`CheckRuntimeRole`) (SEC-04, ADR 0030) | T11 |
| Rôle d'exécution qui crée des objets hors RLS | `CREATE` retiré sur `public` à `PUBLIC`, refus de démarrer si le rôle a `CREATE` sur la base ou sur `public` (SEC-12) | T11 |
| Fonction inter-organisations trop bavarde | fonctions listées (ADR 0012, 0024), métadonnées seulement, toute nouvelle relue comme un changement de sécurité ; `lotor_list_organizations` et `lotor_org_id_by_slug` n'ont aucune garde SQL (l'appelant vérifie en Go) : une injection SQL future les exposerait, risque accepté (SEC-12) | T03 |
| Fuite par les journaux | jamais de mot de passe, jeton, secret ni contenu de SBOM dans les journaux | tous |

### Base de vulnérabilités

| Menace | Parade | Lot |
| --- | --- | --- |
| Archive altérée en transit | HTTPS, somme de contrôle de la liste de distribution vérifiée, ouverture validée avant bascule | T06 |
| Base périmée qui masque de nouvelles CVE | alerte d'administration au-delà de 5 jours | T06 |
| Base différente selon les instances | version cible commune en base, synchronisation avant toute analyse | T06 |
| Archive altérée dans PostgreSQL | SHA-256 et taille revérifiées à chaque synchronisation, avant toute installation ; une archive altérée n'est jamais installée | T06 |
| Archive démesurée (épuisement du disque ou de la mémoire) | taille bornée (`vulndb.max_archive_mib`), téléchargement en flux sur disque, lecture par blocs de 8 Mio | T06 |
| Distribution amont compromise : liste non signée, extraction non bornée | la liste n'est authentifiée que par HTTPS (aucune signature amont) et l'archive par la somme annoncée dans cette même liste ; l'extraction (`curator.Import` d'Anchore) n'est pas bornée en taille décompressée — risque amont accepté, surveillé par l'alerte d'espace disque de l'exploitant (SEC-14) | — |
| Contenu de la base injecté dans les écrans (description, références) | échappement de `html/template`, références limitées aux adresses http(s), texte de la source affiché sans interprétation | T06 |

### Agent serveur

| Menace | Parade | Lot |
| --- | --- | --- |
| Lecture de l'hôte au-delà du nécessaire | utilisateur dédié, seule capacité `CAP_DAC_READ_SEARCH` (lecture), unité systemd durcie (`ProtectSystem=strict`, `NoNewPrivileges`, filtre d'appels système ; `systemd-analyze security` 1,9) ; rien d'autre ne sort que le SBOM et le contexte de l'hôte | T07 |
| Jeton lisible par d'autres comptes | répertoire d'état en `0700`, fichier en `0600` écrit atomiquement, ou credentials systemd chiffrés ; un fichier secret ouvert au groupe ou aux autres est refusé | T07 |
| Jeton envoyé à un tiers | HTTPS seulement, aucune redirection suivie, jeton jamais journalisé | T07 |
| Saturation de l'hôte par le scan | `GOMAXPROCS` et `GOMEMLIMIT` bas, `Nice=19`, `IOSchedulingClass=idle`, `MemoryMax`, durée maximale de scan ; montages réseau et autofs non parcourus | T07 |
| Jeton d'inscription partagé qui choisit son nom d'hôte | sans `project_id`, l'agent est rattaché au projet hôte non affecté qui porte le nom d'hôte **déclaré** : un porteur du jeton peut prendre un projet hôte créé à la main et encore sans agent. Risque accepté sous l'hypothèse « hôtes non compromis à l'inscription » ; jetons d'inscription bornés en durée et en usages, inscription auditée (SEC-13) | T07 |
| Jeton d'agent sans expiration | accepté (ADR 0014) : révocation immédiate, date de dernier usage, rotation documentée (SEC-14) | T04 |
| Confirmation d'inventaire usurpée | un compte rendu n'avance que la date de dernière analyse d'une référence d'hôte confiée à l'agent, et seulement si l'empreinte est celle de l'ensemble courant | T07 |
| Socket Docker = root | accès désactivé par défaut et documenté comme tel | T13 |
| Serveur usurpé | TLS vérifié (autorité privée possible) ; mTLS facultatif, exigé alors sur toute l'API des agents avant la lecture du jeton | T07 |

### Agent dépôt

| Menace | Parade | Lot |
| --- | --- | --- |
| Faux webhook | signature vérifiée (`X-Hub-Signature-256`, `X-Gitlab-Token` en temps constant) ; récepteur en HTTP par défaut : `X-Gitlab-Token` doit passer par un mandataire TLS (documenté) (SEC-14) | T08 |
| Délégué abusé : un administrateur d'organisation (ou un serveur compromis) fait analyser un dépôt hors périmètre | liste blanche obligatoire côté agent (`forges[].allowed_namespaces`, ou `*` explicite), jeton GitHub restreint au seul dépôt ; l'URL de clonage reste reconstruite depuis la base configurée (SEC-10, ADR 0031) | T11 |
| Dépôt piégé (liens symboliques, chemins) | tout accès par `os.Root`, aucun lien suivi hors de l'arborescence, aucun script du dépôt exécuté | T08 |
| Webhook rejoué ou en retard | un webhook n'est qu'un signal : l'agent résout la tête de la référence ; livraisons déjà vues écartées (ADR 0023) | T08 |
| Saturation du récepteur exposé | corps borné, débit limité par IP, réponse immédiate, file bornée | T08 |
| Dépôt trop gros ou trop lent | taille mesurée pendant le clonage (git tué au-delà), délais de clonage et de scan, répertoire supprimé quoi qu'il arrive | T08 |
| Exécution de code du dépôt | aucun crochet git, LFS inerte, Syft sans `go list` ni réseau (`golang.UsePackagesLib=false`) | T08 |
| Vol des secrets de forge | détenus par l'agent seul, jamais en base ni en configuration en clair ; credentials systemd ou fichiers `0600` ; jamais dans les arguments de git, l'URL ni les journaux ; jeton GitHub restreint à `contents: read` et au dépôt analysé ; les droits du jeton GitLab bornent ce qu'une organisation peut faire analyser | T08, T11 |
| Injection d'instructions vers l'IA : le dépôt fait lire au modèle des fichiers hors de l'arborescence ou des secrets | quatre outils seulement (lecture seule, sans réseau ni écriture), tout accès par un `os.Root` sur l'arborescence de l'analyse, chemins absolus et remontées refusés, fichiers sensibles (motifs, clés privées détectées) ni listés, ni lus, ni fouillés et indiscernables d'un fichier absent ; l'analyse ne reçoit aucun secret de l'agent ; prouvé par les dépôts hostiles du corpus avec un faux fournisseur enregistré (ADR 0043, 0044) | T12 |
| Injection d'instructions vers l'IA : le dépôt fait inventer ou accepter un composant | seule sortie acceptée : `submit_candidates` validé par schéma ; vérificateur déterministe seul juge (extrait relu à la ligne, nom et version présents, purl cohérent) ; aucune preuve tirée de la documentation, d'un manifeste ou d'un fichier qui s'adresse au modèle, ni d'un extrait qui cite un purl (ADR 0043) | T12 |
| Fuite de code vers un fournisseur externe non autorisé | IA désactivée par défaut ; fournisseur externe autorisé projet par projet par un administrateur d'organisation, audité ; `ai.forbid_external` sur l'instance ; réglage effectif transmis à l'agent ; client Anthropic sans aucune valeur lue dans l'environnement (ADR 0042, 0043) | T12 |
| Coût ou durée d'analyse incontrôlés (dépôt piège, boucle du modèle) | budget de tours, de jetons, d'octets lus et de durée ; au-delà, SBOM Syft seul marqué incomplet ; analyse incrémentale ; commits intermédiaires sans appel au modèle | T12 |
| Clé d'API du modèle volée | credential systemd ou fichier `0600`, jamais en configuration ni dans les journaux ; erreurs du fournisseur résumées sans corps de réponse | T12 |

### Chaîne d'approvisionnement du projet

| Menace | Parade | Lot |
| --- | --- | --- |
| Dépendance Go vulnérable | `govulncheck` en CI, dépendances validées une à une | T00 → |
| Vulnérabilité activement exploitée dans un binaire publié | SBOM des trois binaires analysés par Grype à chaque build, échec sur une vulnérabilité KEV | T06 |
| Action GitHub détournée | actions épinglées par SHA, permissions `contents: read` | T00 |
| Binaire publié altéré | sommes de contrôle publiées ; signature au lot 3 | T11, T24 |

## Hypothèses

- TLS est terminé par le serveur ou par un mandataire inverse de confiance.
- L'exploitant de PostgreSQL et l'administrateur d'instance sont de confiance ; la RLS
  protège des erreurs de l'application, pas d'un superutilisateur de la base.
- Les hôtes qui portent un agent ne sont pas compromis au moment de l'inscription.
- Derrière un mandataire, seuls les mandataires de `web.trusted_proxies` fournissent l'IP
  du client ; un mandataire de confiance qui ne pose pas `X-Forwarded-For` doit écraser
  `X-Real-IP` (repli d'open-go-base) (SEC-14).
- Tant que `auth.cookie_secure` ne vaut pas `on`, aucun sous-domaine du site n'est hostile :
  sans `__Host-`, un sous-domaine peut écraser les cookies (le jeton CSRF lié à la session
  et la protection inter-origines restent actifs).
