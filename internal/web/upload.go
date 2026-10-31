package web

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// Téléversement d'une archive de la base de vulnérabilités (import manuel, T11).
//
// Le corps d'un formulaire de l'interface est borné à 64 Kio (limitBody) et csrfx lit le
// jeton par PostFormValue, qui, sur un corps multipart, écrirait le fichier entier sur le
// disque avant toute vérification. Pour la seule route de téléversement, uploadGate :
//
//   - n'élargit la borne du corps qu'à un administrateur d'instance authentifié (les autres
//     gardent 64 Kio et reçoivent la réponse habituelle de la garde : 404) ;
//   - lit la première partie du formulaire, qui doit être le jeton CSRF (le gabarit le
//     place avant le fichier, et le navigateur envoie les champs dans l'ordre du
//     document), et le présente à csrfx dans l'en-tête qu'il accepte : la vérification
//     reste celle de csrfx (comparaison au cookie), sans rien lire du fichier ;
//   - laisse au handler le lecteur multipart, qui lit le fichier en flux jusqu'à
//     PostgreSQL ;
//   - repousse les délais de lecture et d'écriture de la connexion : un fichier de
//     plusieurs centaines de Mio dépasse http.read_timeout.

const (
	pathVulnDBImport = "/admin/vulndb/import"
	// csrfFieldName et csrfHeaderName sont les noms par défaut de csrfx.
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	// maxCSRFToken borne la partie du jeton (64 caractères hexadécimaux chez csrfx).
	maxCSRFToken = 256
	// uploadOverhead couvre, au-delà de l'archive, les en-têtes multipart et le jeton.
	uploadOverhead = 64 << 10
)

// isUpload désigne la requête de téléversement.
func isUpload(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == pathVulnDBImport
}

type uploadKey struct{}

// uploadReader renvoie le lecteur multipart posé par uploadGate, positionné après le
// jeton CSRF ; nil si la requête n'en a pas.
func uploadReader(r *http.Request) *multipart.Reader {
	mr, _ := r.Context().Value(uploadKey{}).(*multipart.Reader)
	return mr
}

// uploadGate prépare la requête de téléversement (voir plus haut) ; les autres requêtes
// passent telles quelles.
func (id *identity) uploadGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpload(r) {
			next.ServeHTTP(w, r)
			return
		}
		if v := viewerFrom(r); !v.authenticated() || !v.admin() {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, id.VulnDB.MaxArchive+uploadOverhead)
		rc := http.NewResponseController(w)
		deadline := time.Now().Add(id.VulnDB.UploadTimeout)
		if err := rc.SetReadDeadline(deadline); err != nil {
			id.logger.Debug("délai de lecture du téléversement", "err", err)
		}
		if err := rc.SetWriteDeadline(deadline); err != nil {
			id.logger.Debug("délai d'écriture du téléversement", "err", err)
		}
		mr, err := r.MultipartReader()
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		part, err := mr.NextPart()
		if err != nil || part.FormName() != csrfFieldName {
			// Sans jeton en tête, csrfx refuse la requête (le formulaire est déjà lu en
			// flux : il ne peut plus l'analyser).
			next.ServeHTTP(w, r)
			return
		}
		token, err := io.ReadAll(io.LimitReader(part, maxCSRFToken+1))
		if err == nil && len(token) <= maxCSRFToken {
			r.Header.Set(csrfHeaderName, string(token))
			r = r.WithContext(context.WithValue(r.Context(), uploadKey{}, mr))
		}
		next.ServeHTTP(w, r)
	})
}
