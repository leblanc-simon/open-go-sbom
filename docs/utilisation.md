# Guide d'utilisation

Ce guide décrit l'usage de lotor par les membres d'une organisation. L'installation
et l'exploitation du serveur sont dans [`operations.md`](operations.md) ; les premiers pas
(connexion, organisation, inscription des serveurs et des dépôts) dans le
[guide de démarrage](demarrage.md). Les sections s'ajoutent au fil des lots.

## Recherche

L'écran **Recherche** d'une organisation (`/o/<organisation>/search`) répond à « qui
utilise ce composant, cette version, cette plage de versions ? » et « qui est touché par
cette vulnérabilité ? », dans l'inventaire courant de tous les projets de l'organisation
(projets archivés et références retirées exclus). Il ne sort jamais de l'organisation.

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

Les filtres se combinent : type de projet, étiquette, origine de la détection (Syft ou
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
