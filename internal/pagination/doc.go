// Package pagination fournit la pagination par curseur opaque des listes (§ 15 de
// l'architecture) : toute réponse liste est bornée, et la page suivante se demande avec
// le curseur renvoyé par la précédente.
//
// Le curseur encode la clé de tri du dernier élément rendu (pagination par clé, jamais
// par décalage) : le store la relit et reprend juste après, avec un plan stable.
//
//	type projectKey struct {
//		Name string    `json:"n"`
//		ID   uuid.UUID `json:"i"`
//	}
//
//	limit, err := pagination.Limit(params.Limit, 50, 200)  // 400 error.invalid_limit
//	var after projectKey
//	if params.Cursor != nil {
//		err = pagination.Decode(*params.Cursor, &after)     // 400 error.invalid_cursor
//	}
//	// SELECT … WHERE (name, id) > ($1, $2) ORDER BY name, id LIMIT limit+1
//	page, err := pagination.Build(rows, limit, func(p Project) any {
//		return projectKey{p.Name, p.ID}
//	})
//
// Le curseur n'est pas signé : il ne donne accès à rien de plus qu'une requête sans
// curseur, la RLS bornant toujours la lecture à l'organisation. Un curseur illisible ou
// d'un autre format est refusé avec ErrInvalidCursor.
package pagination
