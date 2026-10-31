package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"

	"leblanc.io/open-go-sbom/internal/agent"
	"leblanc.io/open-go-sbom/internal/api/gen"
	"leblanc.io/open-go-sbom/internal/ingest"
	"leblanc.io/open-go-sbom/internal/locale"
	"leblanc.io/open-go-sbom/internal/project"
	"leblanc.io/open-go-sbom/internal/sbom"
	"leblanc.io/open-go-sbom/internal/web/middleware"
)

// maxContextPart borne la partie context d'un envoi.
const maxContextPart = 16 << 10

// errMissingPart : partie absente ou dans le désordre (context, puis sbom).
var errMissingPart = errors.New("api: partie context ou sbom absente")

// CreateIngestion reçoit un SBOM : la partie context est lue et la référence vérifiée
// avant toute lecture de la partie sbom, qui est passée en flux à ingest.Receive.
func (h *agentAPI) CreateIngestion(ctx context.Context, req gen.CreateIngestionRequestObject) (gen.CreateIngestionResponseObject, error) {
	p, _ := principalFrom(ctx)
	part, err := nextPart(req.Body, "context")
	if err != nil {
		return nil, err
	}
	c, host, err := readContext(part)
	if err != nil {
		return nil, err
	}
	if err := h.Ingest.Authorize(ctx, p.Org, p.AgentID, c); err != nil {
		return nil, err
	}
	if part, err = nextPart(req.Body, "sbom"); err != nil {
		return nil, err
	}
	in, err := h.Ingest.Receive(ctx, p.Org, p.AgentID, c, tooLargeReader{part})
	if err != nil {
		return nil, err
	}
	if host != nil {
		// Le SBOM est reçu : le contexte de l'hôte, informatif, ne le remet pas en cause.
		if err := h.Agents.RecordHost(ctx, p, *host); err != nil {
			middleware.Logger(ctx, h.Logger).Warn("contexte d'hôte ignoré", "err", err)
		}
	}
	out := ingestionOf(ctx, in)
	if in.Duplicate {
		return gen.CreateIngestion200JSONResponse(out), nil
	}
	return gen.CreateIngestion202JSONResponse(out), nil
}

// GetIngestion renvoie une ingestion de l'agent.
func (h *agentAPI) GetIngestion(ctx context.Context, req gen.GetIngestionRequestObject) (gen.GetIngestionResponseObject, error) {
	p, _ := principalFrom(ctx)
	in, err := h.Ingest.Get(ctx, p.Org, p.AgentID, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetIngestion200JSONResponse(ingestionOf(ctx, in)), nil
}

func nextPart(r *multipart.Reader, name string) (*multipart.Part, error) {
	part, err := r.NextPart()
	if errors.Is(err, io.EOF) {
		return nil, errMissingPart
	}
	if err != nil {
		return nil, badMultipart(err)
	}
	if part.FormName() != name {
		return nil, errMissingPart
	}
	return part, nil
}

// badMultipart distingue un corps qui dépasse la borne (413) d'un corps illisible.
func badMultipart(err error) error {
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return ingest.ErrUploadTooLarge
	}
	return &requestError{err: err}
}

// requestError est une requête illisible (400 error.invalid_request).
type requestError struct{ err error }

func (e *requestError) Error() string { return "api: requête illisible : " + e.err.Error() }
func (e *requestError) Unwrap() error { return e.err }

func readContext(part io.Reader) (ingest.Context, *agent.HostContext, error) {
	data, err := io.ReadAll(io.LimitReader(part, maxContextPart+1))
	if err != nil {
		return ingest.Context{}, nil, badMultipart(err)
	}
	if len(data) > maxContextPart {
		return ingest.Context{}, nil, &requestError{err: errors.New("partie context trop longue")}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c gen.IngestionContext
	if err := dec.Decode(&c); err != nil || dec.More() {
		return ingest.Context{}, nil, &requestError{err: errors.New("partie context illisible")}
	}
	host := hostContextOf(c.Host)
	if host != nil {
		if err := host.Validate(); err != nil {
			return ingest.Context{}, nil, err
		}
	}
	out := ingest.Context{ProjectID: c.ProjectId, RefKind: project.RefKind(c.Ref.Kind), RefName: c.Ref.Name,
		AgentVersion: c.AgentVersion, ScannedAt: c.ScannedAt}
	if c.Commit != nil {
		out.Commit = *c.Commit
	}
	return out, host, nil
}

// tooLargeReader signale par ingest.ErrUploadTooLarge un corps qui dépasse la borne de
// limitBody pendant la lecture du SBOM.
type tooLargeReader struct{ r io.Reader }

func (t tooLargeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return n, ingest.ErrUploadTooLarge
	}
	return n, err
}

func ingestionOf(ctx context.Context, in ingest.Ingestion) gen.Ingestion {
	out := gen.Ingestion{Id: in.ID, Status: gen.IngestionStatus(in.Status), ProjectId: in.ProjectID, RefId: in.RefID,
		ReceivedAt: in.ReceivedAt, FinishedAt: in.FinishedAt, ComponentCount: in.Components, SkippedCount: in.Skipped,
		SnapshotId: in.SnapshotID}
	if in.Commit != "" {
		out.Commit = &in.Commit
	}
	if in.Format != "" {
		f := gen.IngestionFormat(in.Format)
		out.Format = &f
	}
	if in.SpecVersion != "" {
		out.SpecVersion = &in.SpecVersion
	}
	if in.Outcome != "" {
		o := gen.IngestionOutcome(in.Outcome)
		out.Outcome = &o
	}
	if in.ErrorKey != "" {
		e := gen.IngestionError{Key: in.ErrorKey, Title: in.ErrorKey, Detail: in.ErrorKey}
		if loc, ok := locale.FromContext(ctx); ok {
			e.Title, e.Detail = loc.T(in.ErrorKey+".title"), loc.T(in.ErrorKey+".text")
		}
		if in.ErrorKey == sbom.KeySchemaInvalid && in.ErrorDetail != "" {
			e.Pointer = &in.ErrorDetail
		}
		out.Error = &e
	}
	return out
}
