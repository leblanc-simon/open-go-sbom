# Modèle de menace

Version 1 (T00, 31 octobre 2026). Tenu à jour à chaque lot qui ajoute une frontière de
confiance, un actif ou un acteur (§ 19 de l'architecture). Gravité évaluée selon l'OWASP
Risk Rating au moment où une faiblesse est trouvée ; ce document liste les menaces et les
parades prévues, et le lot qui les porte.

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
| Requête forgée (CSRF) | csrfx sur l'interface et l'API utilisateur par session | T03 |
| Force brute sur la connexion | limitation par IP dédiée à `/login` et `/login/2fa`, TOTP obligatoire, plafond de codes par défi, journal d'audit des échecs | T03 |
| Énumération des comptes | message d'échec unique (e-mail inconnu, mot de passe faux, compte désactivé), temps égalisé par une comparaison bcrypt factice | T03 |
| Session ouverte sans second facteur | enrôlement obligatoire ; session authentifiée refusée sans méthode enregistrée (`session_auth`) ou sans TOTP actif | T03 |
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
| Déni de service par SBOM énorme ou piégé | corps multipart borné ; bornes en flux (taille reçue, taille décompressée — bombe gzip —, profondeur JSON, nombre de composants, clés comparées sans casse comme le décodeur) avant tout décodage complet ; validation par le schéma officiel avant les décodeurs tiers ; décodage dans un job (jamais dans la requête) borné en durée, panique d'un décodeur convertie en refus ; plafond de jobs par organisation (ADR 0015) | T05 |
| SBOM d'une autre organisation ou d'une autre référence | référence vérifiée par `project.RefForAgent` avant la lecture du SBOM puis dans la transaction qui le stocke ; composants, blobs et ensembles propres à chaque organisation (RLS, clés composites) | T05 |
| Contenu de SBOM dans les journaux ou les erreurs | seuls l'identifiant d'ingestion, la clé d'erreur et des compteurs sont journalisés ; le détail d'une violation de schéma est un pointeur JSON, jamais une valeur | T05 |
| Injection SQL | requêtes paramétrées uniquement (ADR 0004) | tous |
| Saturation de l'API par un hôte | limitation par jeton (`agent_api.rate_limit`), sans gêner les autres hôtes de la même IP | T04 |

### Serveur — base de données

| Menace | Parade | Lot |
| --- | --- | --- |
| Requête qui oublie le filtre d'organisation | RLS forcée sur toute table d'organisation, `InOrg` seul accès, échec franc hors organisation | T01, T03 |
| Ligne qui référence une autre organisation | clés étrangères composites | T03 → |
| Rôle d'exécution trop puissant | refus de démarrer si superutilisateur, `BYPASSRLS` ou propriétaire des tables | T01 |
| Migration altérée après publication | somme SHA-256 vérifiée au démarrage | T01 |
| Fuite de secrets stockés | AES-256-GCM, clé hors base, rotation ; données associées liant chaque chiffré à sa ligne (un chiffré recopié ailleurs ne se déchiffre plus) ; secrets TOTP chiffrés (T03) | T01, T03 |
| Lecture de la base : jetons de session | jetons en clair dans `sessions` (choix d'authx) : une lecture de la base permet de reprendre une session jusqu'à son expiration ; à faire évoluer dans open-go-base (jeton haché) | ouvert |
| Fonction inter-organisations trop bavarde | quatre fonctions listées (ADR 0012), métadonnées seulement, toute nouvelle relue comme un changement de sécurité | T03 |
| Fuite par les journaux | jamais de mot de passe, jeton, secret ni contenu de SBOM dans les journaux | tous |

### Base de vulnérabilités

| Menace | Parade | Lot |
| --- | --- | --- |
| Archive altérée en transit | HTTPS, somme de contrôle de la liste de distribution vérifiée, ouverture validée avant bascule | T06 |
| Base périmée qui masque de nouvelles CVE | alerte d'administration au-delà de 5 jours | T06 |
| Base différente selon les instances | version cible commune en base, synchronisation avant toute analyse | T06 |
| Archive altérée dans PostgreSQL | SHA-256 et taille revérifiées à chaque synchronisation, avant toute installation ; une archive altérée n'est jamais installée | T06 |
| Archive démesurée (épuisement du disque ou de la mémoire) | taille bornée (`vulndb.max_archive_mib`), téléchargement en flux sur disque, lecture par blocs de 8 Mio | T06 |
| Contenu de la base injecté dans les écrans (description, références) | échappement de `html/template`, références limitées aux adresses http(s), texte de la source affiché sans interprétation | T06 |

### Agent serveur

| Menace | Parade | Lot |
| --- | --- | --- |
| Lecture de l'hôte au-delà du nécessaire | lecture seule ; unité systemd durcie (`ProtectSystem`, `NoNewPrivileges`…) | T07 |
| Jeton lisible par d'autres comptes | répertoire d'état en `0700`, fichier en `0600`, ou credentials systemd chiffrés | T07 |
| Socket Docker = root | accès désactivé par défaut et documenté comme tel | T13 |
| Serveur usurpé | TLS vérifié, mTLS facultatif | T07 |

### Agent dépôt

| Menace | Parade | Lot |
| --- | --- | --- |
| Faux webhook | signature vérifiée (`X-Hub-Signature-256`, `X-Gitlab-Token` en temps constant) | T08 |
| Dépôt piégé (liens symboliques, chemins) | tout accès par `os.Root`, aucun lien suivi hors de l'arborescence, aucun script du dépôt exécuté | T08 |
| Vol des secrets de forge | détenus par l'agent seul, jamais en base ni en configuration en clair | T08 |
| Injection d'instructions vers l'IA | outils en lecture seule, sortie à schéma, preuve vérifiée, fichiers sensibles exclus | T12 |

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
