# Mesures de performance

Protocole des cibles chiffrées du cahier des charges et de l'architecture (§ 13 et § 21),
écrit en T06 (ADR 0019) et réutilisé par T09, T10, T11 et T21. Une cible non tenue garde
le lot ouvert, sauf nouvelle cible validée par l'utilisateur.

## Machine de référence

Poste de développement de l'utilisateur (décision du 31 octobre 2026) : 16 cœurs, 30 Go
de RAM, disque NVMe, Linux, PostgreSQL 16 local avec la configuration par défaut de la
distribution. Chaque mesure consignée ci-dessous indique la machine qui l'a produite ;
une mesure faite sur une machine moins puissante que la référence et qui tient la cible
vaut pour la référence.

## Protocole

- **Base** : base jetable de `dbtest` (migrations appliquées), requêtes par le **rôle
  d'exécution**, donc **RLS active** ; `ANALYZE` passé par le rôle propriétaire après la
  génération du jeu.
- **Répétitions** : au moins 20 passages par mesure (50 pour les lectures), **95e
  centile** retenu ; médiane et maximum consignés.
- **Cache froid et chaud** : froid = premier passage après l'ouverture de la base Grype
  (ou après la génération du jeu) ; chaud = passages suivants. Le cache du système de
  fichiers n'est pas vidé (pas de droits d'administration requis) : le froid mesure les
  caches applicatifs (Grype, PostgreSQL), pas le disque.
- **Sans `-race`**, binaires de test compilés normalement.

## Jeu de données synthétique

`internal/benchdata.Generate(ctx, pool, org, slug, benchdata.Reference())` : une
organisation de **1 000 projets** (dépôts, une branche `main` chacun), **1 million de
liens** composant × ensemble (1 000 composants par projet, distincts, pris par un pas
multiplicatif parmi **60 013 composants** répartis sur npm, maven, pypi, golang et deb),
un instantané courant par référence, **5 000 vulnérabilités** au catalogue (2 % critiques,
15 % élevées, 50 % moyennes, 30 % faibles, 3 % inconnues, 1 % KEV, EPSS uniforme) et
environ **75 000 constats** (un composant sur 20 vulnérable, un sur 40 deux fois ; un
constat sur dix résolu). Génération en SQL `generate_series`, déterministe, sous la RLS :
environ une minute. `benchdata.SyntheticCycloneDX(n, variante)` produit un SBOM
CycloneDX 1.6 de n composants (dix paquets réellement vulnérables, le reste synthétique),
chaque variante étant un inventaire distinct.

## Commandes

```bash
make bench                         # jeu de référence et lectures des écrans (OGSBOM_BENCH=1)
OGSBOM_TEST_GRYPEDB_DIR=/chemin/db make test-grypedb   # vraie base Grype : acceptation et 5 000 composants
```

`OGSBOM_TEST_GRYPEDB_DIR` désigne le répertoire racine d'une base Grype v6 installée (il
contient `6/vulnerability.db`), par exemple celui de la commande `grype db update`.

## Résultats

### T06 — Ingestion et analyse d'un SBOM de 5 000 composants (cible : 30 s au 95e centile)

`TestIngestAndAnalyze5000` : réception, décodage et rangement, analyse Grype (base v6.1.10
du 30 octobre 2026) et écriture des constats, de bout en bout ; chaque passage est un
nouvel inventaire (variante), donc une analyse complète.

| Machine | Froid | Chaud p50 | Chaud p95 | Maximum | dont ingestion p95 |
| --- | --- | --- | --- | --- | --- |
| Environnement de réalisation (4 cœurs Xeon 2,8 GHz, 15 Gio) | 6,26 s | 6,06 s | **6,45 s** | 6,45 s | 0,70 s |

Ouverture de la base Grype (somme xxh64 comprise) : 2 à 4 s, au démarrage et à chaque
bascule, hors mesure. Cible tenue.

### T06 — Lectures des écrans sur le jeu de référence (sans cible chiffrée)

| Lecture | p50 | p95 | Maximum |
| --- | --- | --- | --- |
| Onglet « Constats » (page de 50, tri par risque) | 3,9 ms | 5,4 ms | 6,4 ms |
| Décomptes par référence d'un projet | 0,9 ms | 1,3 ms | 2,0 ms |
| Fiche vulnérabilité (constats de l'organisation) | 9,7 ms | 13,6 ms | 20,9 ms |
| Fiche composant (famille d'un purl) | 1,5 ms | 3,4 ms | 3,9 ms |

Environnement de réalisation (4 cœurs, 15 Gio) ; génération du jeu : 51 s.
