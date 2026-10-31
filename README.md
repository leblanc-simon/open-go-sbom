# open-go-sbom

Plateforme open source de gestion de SBOM (Software Bill of Materials) par projet, dépôt git
ou serveur. Deux agents produisent les SBOM ; un serveur central les historise, les analyse
chaque jour avec Grype et offre recherche transverse, triage et tableaux de bord, pour
plusieurs organisations.

| Binaire | Rôle |
| --- | --- |
| `ogsbom-server` | interface web, API REST, traitements de fond |
| `ogsbom-host-agent` | agent serveur : inventaire d'un hôte Linux et de ses conteneurs |
| `ogsbom-repo-agent` | agent dépôt : clonage des dépôts des forges et analyse Syft |

État : préversion **0.1.0** (lot 1 · MVP inventaire : agents serveur et dépôt, ingestion,
analyse Grype quotidienne, recherche transverse, tableau de bord, organisations isolées,
comptes locaux avec TOTP). Binaires et paquets : page des versions GitHub ; évolutions :
[`CHANGELOG.md`](CHANGELOG.md).

## Démarrer

- [Guide de démarrage](docs/demarrage.md) · [Getting started (English)](docs/getting-started.md)
- [Installation et exploitation](docs/operations.md)
- [Guide d'utilisation : recherche](docs/utilisation.md)

## Développement

Prérequis : Go 1.26, `make`, PostgreSQL 16 pour les tests d'intégration
(`docker compose -f deploy/compose.yaml up -d`).

```bash
make ci        # toutes les vérifications, identiques à la CI
make build     # bin/ogsbom-server, bin/ogsbom-host-agent, bin/ogsbom-repo-agent
make run       # serveur local (cp config.example.yaml config.yaml)
make help      # liste des cibles
```

## Documentation

- [Cahier des charges](docs/cahier-des-charges.md)
- [Architecture de référence](specs/architecture.md)
- [Lots techniques](specs/README.md)
- [Exploitation](docs/operations.md)
- [Mesures de performance](docs/benchmarks.md)
- [Journal des modifications](CHANGELOG.md)
- [Décisions d'architecture](docs/adr/)
- [Modèle de menace](docs/security/threat-model.md)

## Licence

[WTFPL](LICENSE).
