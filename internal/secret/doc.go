// Package secret chiffre les secrets stockés en base (secrets des canaux de notification,
// secret client OIDC…) en AES-256-GCM, avec des clés versionnées pour la rotation.
//
// La configuration fournit des clés de 32 octets nommées (secrets.keys) et le nom de la
// clé active (secrets.active_key). La clé active chiffre ; les autres ne servent plus qu'à
// déchiffrer. Le nom de la clé est stocké à côté du chiffré :
//
//	ct, keyID, err := box.Seal(plaintext, []byte("notification_channel:"+id))
//	// INSERT … (secret, secret_key_id) VALUES (ct, keyID)
//	pt, err := box.Open(ct, keyID, []byte("notification_channel:"+id))
//
// Les données associées (aad) lient le chiffré à sa ligne : recopié dans une autre ligne,
// il ne se déchiffre plus. Rotation : ajouter une clé, la rendre active, puis réécrire les
// chiffrés dont NeedsRotation est vrai avec Rotate ; l'ancienne clé se retire ensuite.
//
// Format du chiffré, versionné : un octet de version (1), un nonce aléatoire de 12 octets,
// puis le chiffré GCM et son étiquette. Le nom de la clé entre dans les données
// authentifiées : un chiffré présenté avec un autre nom de clé est refusé.
package secret
