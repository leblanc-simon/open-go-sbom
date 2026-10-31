# Système de fichiers d'exemple de l'agent serveur

Racine inventoriée par les tests d'`internal/hostagent` (`scan.root`) : un hôte
« Debian 12 » factice qui réunit, pour les besoins du test, une base de chaque nature.

| Chemin | Contenu attendu dans le SBOM |
| --- | --- |
| `etc/os-release` | Debian 12 (distribution du SBOM) |
| `var/lib/dpkg/status` | 3 paquets deb écrits à la main : `base-files`, `libc6` (source `glibc`), `openssl` |
| `var/lib/rpm/Packages` | base RPM BerkeleyDB réelle d'un paquet (`libuuid`), jeu d'essai `pkg/testdata/libuuid` de `github.com/anchore/go-rpmdb` v0.2.2 (licence MIT) |
| `lib/apk/db/installed` | 2 paquets apk écrits à la main : `musl`, `busybox` |
| `usr/lib/python3/dist-packages/requests-2.31.0.dist-info` | paquet Python `requests` |

Leurres, qui ne doivent **jamais** apparaître dans le SBOM (tous en version `9.9.9`) :

| Chemin | Raison de l'exclusion |
| --- | --- |
| `var/lib/docker/…`, `var/lib/containers/…`, `var/lib/containerd/…` | stockages des moteurs de conteneurs (T13) |
| `home/alice/.local/share/containers/…` | stockage de Podman sans root |
| `proc/…` | système de fichiers virtuel |
| `mnt/nfs/…` | point de montage réseau (montage simulé dans le test) |
| `srv/cache/…` | exclusion configurée (`scan.exclude`) |
