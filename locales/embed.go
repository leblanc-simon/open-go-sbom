// Package locales embarque les traductions de l'interface : un fichier YAML par langue,
// nommé d'après son étiquette BCP 47 (fr.yaml, en.yaml).
//
// Clés en anglais, de la forme écran.élément (home.heading), regroupées en YAML imbriqué.
// Racines transverses : app.*, layout.*, nav.*, theme.*, footer.*, error.*, puis format.*,
// status.*, severity.*, validation.* au fil des lots. Une erreur de clé K porte K.title et
// K.text. Les noms de feuilles réservés par go-i18n (description, hash, id, translation,
// leftdelim, rightdelim, zero, one, two, few, many, other) ne s'emploient pas comme
// éléments : go-i18n prendrait la table pour un message. Les tests de ce paquet vérifient
// que chaque langue a les mêmes clés.
package locales

import "embed"

// FS contient les fichiers *.yaml à la racine du paquet.
//
//go:embed *.yaml
var FS embed.FS
