# Guide d'utilisation

Ce guide décrit l'usage de lotor par les membres d'une organisation. L'installation
et l'exploitation du serveur sont dans [`operations.md`](operations.md) ; les premiers pas
(connexion, organisation, inscription des serveurs et des dépôts) dans le
[guide de démarrage](demarrage.md). Les sections s'ajoutent au fil des lots.

## Recherche

L'écran **Recherche** d'une organisation (`/o/<organisation>/search`) répond à « qui
utilise ce composant, cette version, cette plage de versions ? » et « qui est touché par
cette vulnérabilité ? », dans l'inventaire courant des projets de l'organisation que vous
voyez (ceux de vos équipes, ou tous si vous administrez l'organisation ; projets archivés
et références retirées exclus). Il ne sort jamais de l'organisation.

### Ce qu'on peut chercher

Une seule barre ; le type de requête est déduit de sa forme et rappelé sous la barre
(« Interprété comme »).

| Saisie | Type | Résultat |
| --- | --- | --- |
| `log4j-core` | nom de composant | les composants dont le nom contient le texte (sans casse), toutes versions et tous écosystèmes ; s'il n'y en a aucun, ceux dont le nom lui ressemble (faute de frappe), signalés comme approchés. Moins de trois caractères : nom exact. |
| `pkg:npm/lodash` | purl | toutes les versions du paquet |
| `pkg:npm/lodash@4.17.20` | purl avec version | cette version, quels que soient ses qualificatifs ; ajouter des qualificatifs (`?arch=amd64`) restreint encore |
| `pkg:npm/lodash vers:npm/<4.17.21` | purl et plage | les versions du paquet dans la plage, comparées selon les règles de l'écosystème |
| `CVE-2021-44228`, `GHSA-jfh8-c2jp-5v3q` | vulnérabilité | les projets touchés, avec le statut du constat et la version corrigée ; un GHSA est ramené à son CVE |
| `sha256:0925e8ad…` ou les 64 caractères seuls | empreinte | les composants qui portent ce fichier, et leurs projets |

La recherche par licence (`license:…`) arrive avec l'analyse des licences.

### Plages de versions

Une plage suit le format [vers](https://github.com/package-url/purl-spec/blob/main/VERSION-RANGE-SPEC.rst) :
`vers:<schéma>/<contraintes>`, contraintes séparées par `|`, comparateurs `=` (par défaut),
`!=`, `<`, `<=`, `>`, `>=`, ou `*` pour toutes les versions. Exemples :

- `vers:npm/<4.17.21` : avant 4.17.21 ;
- `vers:maven/>=2.0-beta9|<2.15.0` : de 2.0-beta9 inclus à 2.15.0 exclu ;
- `vers:pypi/>=1.0|!=1.5|<2.0` : de 1.0 à 2.0 sauf 1.5 ;
- `vers:deb/<1:1.0` : avec l'époque Debian.

Le schéma doit être celui du paquet (`vers:npm` pour `pkg:npm`, `vers:deb` pour `pkg:deb`,
`vers:alpine` pour `pkg:apk`…). Les versions sont comparées selon l'écosystème (npm,
Maven, PEP 440, RubyGems, modules Go, Debian, RPM, Alpine, semver pour les autres), jamais
comme du texte : `4.9.0` est bien avant `4.17.21`. Une plage ne s'applique qu'à un purl
sans version : une recherche par nom n'en accepte pas.

Sous les résultats, l'écran indique combien d'occurrences du paquet sont hors de la plage
(avec un lien pour retirer la plage), et liste les versions **non comparables** (par
exemple `latest`) : on ne peut pas dire si elles sont dans la plage, elles ne sont donc pas
affichées, mais elles ne sont pas oubliées.

### Filtres, ordre et partage

Les filtres se combinent : type de projet (« Inclure les conteneurs » ajoute les
conteneurs des serveurs, écartés sinon ; paramètre `containers=1`), étiquette, origine de la détection (Syft ou
IA), vulnérabilité activement exploitée (KEV), sévérité maximale (ou « sans
vulnérabilité »), et, pour une recherche par vulnérabilité, les constats déjà résolus.
Dans un même filtre, les valeurs cochées s'additionnent. Les résultats sont groupés par
projet, triés par risque, par nom ou par instantané le plus récent, vingt projets par page.

Requête, filtres et ordre sont dans l'adresse de la page : la copier suffit pour partager
exactement le même résultat avec un autre membre de l'organisation.

### Export

« Exporter en CSV » et « Exporter en JSON » donnent toutes les occurrences de la
recherche (pas seulement la page affichée), avec projet, référence, commit, composant,
version, purl, origine, vulnérabilités ouvertes, sévérité, KEV, risque et versions
corrigées. Dans le CSV, une cellule qui commencerait par `=`, `+`, `-` ou `@` est préfixée
d'une apostrophe, pour qu'un tableur ne l'interprète pas comme une formule.

### Par l'API

La même recherche existe dans l'API, avec les mêmes paramètres et les mêmes résultats :

```bash
curl -H "Authorization: Bearer $LOTOR_TOKEN" \
  "https://lotor.example/api/v1/orgs/<organisation>/search?q=CVE-2021-44228&kev=1"
curl -H "Authorization: Bearer $LOTOR_TOKEN" -o lodash.csv \
  "https://lotor.example/api/v1/orgs/<organisation>/search/export?format=csv&q=pkg:npm/lodash+vers:npm/%3C4.17.21"
```

Le jeton est un **jeton d'accès personnel**, créé depuis « Mon compte » → « Jetons
d'accès » : il expire (7 jours à 1 an), il est affiché une seule fois, il se révoque à
tout moment, et il ne donne que la lecture de ce que votre compte voit, dans les
organisations dont vous êtes membre au moment de chaque requête. Le contrat de l'API est
dans `api/openapi.yaml` (opérations `searchOrganization` et `exportSearch`).

## Équipes, rôles et invitations

Chaque projet appartient à une **équipe**. Vous voyez les projets de vos équipes — dans
les listes, la recherche, le tableau de bord, les fiches des vulnérabilités et des
composants, les exports et l'API —, et vous y agissez selon votre **rôle d'équipe** :

| Rôle d'équipe | Ce qu'il permet sur les projets de l'équipe |
| --- | --- |
| Lecteur | Consulter les projets, leurs constats, instantanés et SBOM, et les agents de l'équipe |
| Analyste | En plus : demander un scan à un agent serveur, trier les constats (lot de triage) |
| Administrateur d'équipe | En plus : créer, modifier, archiver un projet de l'équipe, le confier à un agent, le rattacher à une autre équipe qu'il administre aussi ; gérer les agents et jetons d'inscription de l'équipe ; ajouter et retirer les membres de l'équipe |

Un **administrateur de l'organisation** voit et gère tout : il crée, renomme et supprime
les équipes, invite et retire les membres, règle l'organisation et lit son journal. Un
membre qui n'est dans aucune équipe ne voit aucun projet. La matrice complète est dans
[`security/permissions.md`](security/permissions.md).

**Équipes.** La page **Équipes** liste vos équipes (toutes pour un administrateur de
l'organisation). La page d'une équipe montre ses membres et mène à ses projets ; son
administrateur y ajoute un membre de l'organisation par son adresse, change son rôle ou le
retire. Une équipe ne se supprime qu'une fois tous ses projets rattachés à une autre.

**Agents.** Un agent d'équipe ne sert que les projets de son équipe et se gère par ses
administrateurs ; un agent d'organisation (sans équipe) sert toutes les équipes et ne se
gère que par les administrateurs de l'organisation. Un jeton d'inscription appartient à
une équipe : les serveurs qu'il inscrit, et leurs agents, entrent dans cette équipe.

**Invitations.** Pour rejoindre une organisation, un compte doit être **invité** par un de
ses administrateurs, puis **accepter** l'invitation depuis « Mon compte » → « Invitations »
(elle vaut 30 jours ; la décliner la supprime). L'administrateur ne sait pas, en invitant,
si l'adresse a déjà un compte : un compte créé plus tard par l'administration de
l'instance peut encore accepter l'invitation tant qu'elle court.

## Conteneurs des serveurs

Quand l'agent d'un serveur inventorie aussi ses conteneurs (option de l'agent, désactivée
par défaut : voir `docs/operations.md`, « Conteneurs »), chaque conteneur qui tourne
devient un **projet enfant** du projet du serveur, avec son propre SBOM, ses constats et
son historique.

- **Identité** : un service Compose forme un seul projet, nommé `serveur/projet/service`,
  quel que soit le nombre de ses répliques et même s'il est recréé à chaque déploiement ;
  un conteneur lancé sans Compose est suivi par son nom. Deux services sur la même image
  font deux projets, mais l'image n'est analysée qu'une fois.
- **Équipe** : un conteneur appartient toujours à l'équipe de son serveur ; rattacher le
  serveur à une autre équipe y emmène ses conteneurs, et voir le serveur, c'est voir ses
  conteneurs.
- **Fiche du serveur** : le tableau « Conteneurs et constats par périmètre » montre, pour
  le serveur et chacun de ses conteneurs, l'image, l'état (en cours, absent, archivé) et
  les vulnérabilités ouvertes par sévérité. Chaque projet compte ses vulnérabilités
  distinctes : une CVE présente sur le serveur et dans deux conteneurs compte trois fois
  au total, une CVE présente dans deux composants d'un même conteneur une fois.
- **Fiche d'un conteneur** : moteur (Docker, Podman), image et son empreinte, projet et
  service Compose, noms des répliques, démarrage, dernier signalement par l'agent ; son
  fil d'Ariane remonte au serveur.
- **Disparition** : un conteneur que l'agent ne signale plus depuis 7 jours (réglage du
  serveur) est archivé ; il revient de lui-même, avec son historique, s'il redémarre.
  Archiver soi-même le projet d'un conteneur (Paramètres) arrête son inventaire, même
  s'il tourne encore.
- **Listes et recherche** : les conteneurs n'y figurent que si « Inclure les conteneurs »
  est coché ; le tableau de bord de l'organisation, lui, les compte avec les autres
  projets.
