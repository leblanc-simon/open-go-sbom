# Schémas JSON embarqués

Schémas officiels utilisés pour valider les SBOM reçus (décision de T05), téléchargés le
31 octobre 2026. Ils sont copiés sans modification ; ne pas les éditer à la main.

| Fichier | Source | Étiquette | SHA-256 |
| --- | --- | --- | --- |
| `cyclonedx-1.5/bom-1.5.schema.json` | `CycloneDX/specification`, `schema/` | `1.5` | `067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b` |
| `cyclonedx-1.5/spdx.schema.json` | idem | `1.5` | `4f6e2b05c05d26a4f2dc5879fbc2fca94b0a28db46289d0c51345621b71cfbfc` |
| `cyclonedx-1.5/jsf-0.82.schema.json` | idem | `1.5` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `cyclonedx-1.6/bom-1.6.schema.json` | idem | `1.6` | `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93` |
| `cyclonedx-1.6/spdx.schema.json` | idem | `1.6` | `baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e` |
| `cyclonedx-1.6/jsf-0.82.schema.json` | idem | `1.6` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `cyclonedx-1.7/bom-1.7.schema.json` | idem | `1.7` | `df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221` |
| `cyclonedx-1.7/spdx.schema.json` | idem | `1.7` | `54a6288292bc6c90b0d3952f5f939f17436fa76704ffe68a46e5b78539c7cc1b` |
| `cyclonedx-1.7/jsf-0.82.schema.json` | idem | `1.7` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `cyclonedx-1.7/cryptography-defs.schema.json` | idem | `1.7` | `018ea7f78b5208ec647cfd10f669cc9c26aba6aceb79c4da7f9c0ef4c99b60de` |
| `spdx-2.3/spdx-schema.json` | `spdx/spdx-spec`, `schemas/spdx-schema.json` | `v2.3` | `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b` |

URL de téléchargement : `https://raw.githubusercontent.com/<dépôt>/<étiquette>/<chemin>`.

Licences : spécification CycloneDX sous Apache-2.0 (`LICENSE-cyclonedx.txt`, fichier
`LICENSE` de l'étiquette `1.7`) ; spécification SPDX sous CC-BY-3.0 (`LICENSE-spdx.txt`,
fichier `LICENSE` de l'étiquette `v2.3`).

Chaque version de CycloneDX a son propre compilateur : les trois versions publient
`spdx.schema.json` et `jsf-0.82.schema.json` à la même URL (`http://cyclonedx.org/schema/…`)
avec des contenus différents. Aucune référence n'est chargée depuis le réseau.
