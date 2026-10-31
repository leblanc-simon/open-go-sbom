package agentclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/textproto"

	"leblanc.io/open-go-sbom/internal/agentclient/gen"
)

// Upload envoie un SBOM (JSON, non compressé : le client le compresse) pour la référence
// que décrit ic. Le corps multipart (context puis sbom en gzip) est construit une fois et
// rejoué à chaque tentative. La réponse est l'ingestion créée (202) ou, pour un envoi
// identique d'un dépôt, l'ingestion existante (200) ; Wait en suit l'état.
func (c *Client) Upload(ctx context.Context, ic gen.IngestionContext, sbom []byte) (gen.Ingestion, error) {
	body, contentType, err := multipartBody(ic, sbom)
	if err != nil {
		return gen.Ingestion{}, err
	}
	rsp, err := c.gen.CreateIngestionWithBodyWithResponse(withOp(ctx, "createIngestion"), contentType, bytes.NewReader(body), c.editor(""))
	if err != nil {
		return gen.Ingestion{}, wrapTransport("createIngestion", err)
	}
	switch {
	case rsp.JSON202 != nil:
		return *rsp.JSON202, nil
	case rsp.JSON200 != nil:
		return *rsp.JSON200, nil
	}
	return gen.Ingestion{}, responseError("createIngestion", rsp.HTTPResponse, rsp.Body)
}

// multipartBody construit le corps d'un envoi : partie context (JSON), puis partie sbom
// compressée en gzip, dans cet ordre (le serveur vérifie la référence avant de lire le
// SBOM).
func multipartBody(ic gen.IngestionContext, sbom []byte) ([]byte, string, error) {
	if len(sbom) == 0 {
		return nil, "", fmt.Errorf("agentclient: SBOM vide")
	}
	ctxJSON, err := json.Marshal(ic)
	if err != nil {
		return nil, "", fmt.Errorf("agentclient: contexte de l'envoi : %w", err)
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="context"`},
		"Content-Type":        {"application/json"},
	})
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(ctxJSON); err != nil {
		return nil, "", err
	}
	if part, err = w.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="sbom"; filename="sbom.json.gz"`},
		"Content-Type":        {"application/gzip"},
	}); err != nil {
		return nil, "", err
	}
	zw, err := gzip.NewWriterLevel(part, gzip.BestCompression)
	if err != nil {
		return nil, "", err
	}
	if _, err := zw.Write(sbom); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}
