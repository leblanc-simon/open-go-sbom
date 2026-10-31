# Guide de démarrage

*[English version](getting-started.md)*

Ce guide mène d'une instance installée à un premier parc inventorié et interrogé :
connexion, organisation, serveurs, dépôts, lecture des résultats. L'installation du
serveur et des agents est décrite dans [`operations.md`](operations.md) ; l'usage détaillé
de la recherche dans [`utilisation.md`](utilisation.md).

## 1. Se connecter

1. L'exploitant vous transmet l'adresse de l'instance (par exemple
   `https://sbom.example.org`), votre adresse e-mail de connexion et un **mot de passe
   temporaire**, affiché une seule fois à la création du compte.
2. Ouvrez l'adresse et connectez-vous. À la première connexion, l'écran **Configurez votre
   second facteur** affiche un QR code : scannez-le avec une application d'authentification
   (FreeOTP, Aegis, Google Authenticator, 1Password…), ou recopiez la clé affichée, puis
   saisissez le code à six chiffres. Le second facteur est obligatoire pour tous les
   comptes locaux.
3. Choisissez ensuite votre mot de passe définitif (12 caractères au moins).

Ensuite, chaque connexion demande le mot de passe puis un code. Perte du téléphone : un
administrateur d'instance réinitialise votre second facteur et vous transmet un nouveau
mot de passe temporaire. **Mon compte** (en haut à droite) règle la langue (français ou
anglais) et le thème, change le mot de passe et gère vos jetons d'accès.

## 2. Créer l'organisation (administrateur d'instance)

Une **organisation** regroupe des projets et leurs membres ; rien ne passe d'une
organisation à l'autre.

1. **Administration › Comptes** : créez les comptes des futurs membres (le mot de passe
   temporaire s'affiche une fois, à transmettre par un canal sûr). Désignez un second
   administrateur d'instance : l'interface le rappelle tant qu'il n'y en a qu'un.
2. **Administration › Organisations** : créez l'organisation (identifiant court, par
   exemple `infra`, nom, langue) et désignez son premier administrateur.
3. Dans l'organisation, **Membres** : ajoutez les comptes avec leur rôle — **lecteur**
   (consulte), **analyste** (consulte et demande des scans), **administrateur** (gère
   projets, agents, membres et paramètres).

## 3. Inventorier des serveurs

1. **Agents › Inscrire des serveurs** (administrateur de l'organisation) : choisissez la
   durée de validité, le nombre de serveurs à inscrire et, au besoin, des étiquettes
   (`env=prod`). Le **jeton d'inscription** et les commandes d'installation s'affichent
   une seule fois.
2. Sur chaque serveur, l'exploitant installe le paquet `lotor-host-agent`, renseigne
   l'adresse du serveur, dépose le jeton et démarre l'agent
   ([`operations.md`](operations.md#agent-serveur)).
3. Au premier passage, le serveur apparaît dans **Projets** avec son système, son noyau
   et son architecture, puis son premier **instantané** et ses **constats** quelques
   secondes plus tard. L'agent rescanne chaque jour et n'envoie un SBOM que si
   l'inventaire a changé.
4. Pour un inventaire immédiat (après une mise à jour du serveur, par exemple) : fiche du
   projet › **Scanner maintenant** (analyste ou administrateur). L'agent le lance à son
   prochain signal de vie (5 minutes au plus en mode démon).

## 4. Inventorier des dépôts

1. L'exploitant met en place l'**agent dépôt** de l'organisation, avec une GitHub App ou un
   compte de service GitLab ([`operations.md`](operations.md#agent-dépôt)) ; il crée pour
   cela l'agent dans **Agents › Nouvel agent dépôt**.
2. **Projets › Nouveau projet**, type **Dépôt** : nom, URL du dépôt sur la forge
   (`https://github.com/acme/app`), branches suivies (une par ligne, par exemple `main`),
   étiquettes suivies éventuelles.
3. Sur la fiche du projet, confiez-le à l'agent dépôt. L'agent l'analyse à son prochain
   passage (15 minutes au plus), puis à chaque push reçu par webhook.

## 5. Lire les résultats

- **Tableau de bord** (accueil de l'organisation) : constats ouverts par sévérité,
  vulnérabilités activement exploitées (**KEV**), tendance, délai médian de correction,
  agents muets depuis 7 jours, projets et composants les plus exposés.
- **Fiche d'un projet** : onglet **Constats** (vulnérabilités ouvertes, triées par risque,
  avec la version corrigée), onglet **Instantanés** (SBOM reçus, téléchargeables tels
  quels ou en CycloneDX 1.6 et SPDX 2.3).
- **Fiche d'une vulnérabilité** : description, scores, et les projets de l'organisation
  qu'elle touche.
- La base de vulnérabilités est mise à jour chaque jour et tout le parc est réanalysé :
  un constat apparaît ou se résout sans nouvel envoi des agents.

## 6. Interroger le parc

**Recherche** répond à « qui utilise ce composant ? » et « qui est touché par cette
CVE ? » sur l'inventaire courant de tous les projets de l'organisation :

| Saisie | Résultat |
| --- | --- |
| `CVE-2023-48795` ou `GHSA-45x7-px36-x8w8` | projets touchés, composants, statut, version corrigée |
| `openssl` | composants dont le nom contient le texte |
| `pkg:golang/golang.org/x/crypto vers:golang/<0.17.0` | versions d'un paquet dans une plage |
| `sha256:…` | composants qui portent ce fichier |

Les filtres (type de projet, étiquette, KEV, sévérité) et l'ordre sont dans l'adresse de
la page : la copier partage le même résultat. **Exporter en CSV / JSON** donne toutes les
occurrences. Détails : [`utilisation.md`](utilisation.md).

## 7. Automatiser par l'API

**Mon compte › Jetons d'accès** : créez un jeton personnel (7 jours à 1 an, code TOTP
demandé, affiché une seule fois). Il donne la lecture de ce que votre compte voit :

```bash
curl -H "Authorization: Bearer $LOTOR_TOKEN" \
  "https://sbom.example.org/api/v1/orgs/infra/search?q=CVE-2023-48795"
```

Le contrat de l'API est dans [`api/openapi.yaml`](../api/openapi.yaml).
