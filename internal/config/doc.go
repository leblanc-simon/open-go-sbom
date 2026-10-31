// Package config compose la configuration du serveur : fragments d'open-go-base (appconf)
// et fragments propres au projet, chargés depuis un fichier YAML (-c, config.yaml par
// défaut) s'il existe, sinon depuis les variables OGSBOM_*. Les variables d'environnement
// l'emportent sur le fichier.
//
//	cfg, err := config.Load("ogsbom-server", version) // --help et --version terminent
//
// Load part de Defaults (pilote postgres, langue fr, journaux info), puis Validate vérifie
// l'ensemble et renvoie une erreur par champ fautif, qui nomme son chemin YAML et sa
// variable (database.driver (OGSBOM_DB_DRIVER) : …). Fields énumère les feuilles de la
// configuration ; config.example.yaml, à la racine du dépôt, les documente toutes.
//
// Limite connue d'appconf v1.0.1 : --help affiche les défauts d'appconf
// (OGSBOM_DB_DRIVER « sqlite », OGSBOM_I18N_DEFAULT_LANGUAGE « en », OGSBOM_LOG_LEVEL
// « error ») et non ceux de Defaults, qui s'appliquent pourtant ; OGSBOM_I18N_DIR est sans
// effet, les traductions étant embarquées.
package config
