package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Moteurs de conteneurs reconnus. containerd seul, sans Docker ni Podman, relève de T22.
const (
	EngineDocker = "docker"
	EnginePodman = "podman"
)

// DefaultSockets sont les sockets interrogées quand containers.sockets est vide : Docker,
// puis Podman avec root. Une socket absente est ignorée.
var DefaultSockets = []string{"/run/docker.sock", "/run/podman/podman.sock"}

// Bornes des réponses d'un moteur.
const (
	maxEngineList    = 16 << 20
	maxEngineInspect = 1 << 20
)

// Container est un conteneur en cours d'exécution, tel que le moteur le décrit.
type Container struct {
	ID        string
	Names     []string // sans la barre initiale de l'API Docker
	Image     string   // référence de l'image (nginx:1.27, ou son identifiant)
	ImageID   string   // sha256:…
	Labels    map[string]string
	StartedAt time.Time
}

// ContainerEngine est un moteur de conteneurs interrogé par l'agent.
type ContainerEngine interface {
	// Name renvoie le moteur détecté (EngineDocker ou EnginePodman), ou le chemin de sa
	// socket avant la détection.
	Name() string
	// Socket renvoie le chemin de la socket.
	Socket() string
	// Containers détecte le moteur et liste les conteneurs en cours d'exécution.
	Containers(ctx context.Context) ([]Container, error)
	// ExportImage écrit l'image imageID au format docker-archive (docker save) dans w,
	// max octets au plus.
	ExportImage(ctx context.Context, imageID string, w io.Writer, max int64) error
}

// ErrEngineAbsent : aucune socket au chemin configuré (moteur non installé ou arrêté).
var ErrEngineAbsent = errors.New("hostagent: socket du moteur de conteneurs absente")

// ErrImageTooLarge : l'image dépasse containers.max_image_mib.
var ErrImageTooLarge = errors.New("hostagent: image trop grosse (containers.max_image_mib)")

// SocketEngine parle à l'API Docker d'un moteur (Docker, ou l'API compatible de Podman)
// par sa socket Unix, en HTTP, sans bibliothèque cliente : quatre appels suffisent
// (/version, /containers/json, /containers/{id}/json, /images/{id}/get).
type SocketEngine struct {
	socket string
	client *http.Client
	name   string
}

// NewSocketEngine prépare le client d'une socket ; rien n'est ouvert avant le premier
// appel. timeout borne chaque appel, hors export d'une image (borné par le contexte).
func NewSocketEngine(socket string, timeout time.Duration) *SocketEngine {
	tr := &http.Transport{
		// Jamais de mandataire : la connexion est locale.
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	return &SocketEngine{socket: socket, client: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Name renvoie le moteur détecté, ou la socket avant le premier appel.
func (e *SocketEngine) Name() string {
	if e.name == "" {
		return e.socket
	}
	return e.name
}

// Socket renvoie le chemin de la socket.
func (e *SocketEngine) Socket() string { return e.socket }

// Close libère les connexions inactives.
func (e *SocketEngine) Close() { e.client.CloseIdleConnections() }

// get lit une réponse JSON bornée.
func (e *SocketEngine) get(ctx context.Context, path string, max int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine"+path, nil)
	if err != nil {
		return err
	}
	rsp, err := e.client.Do(req)
	if err != nil {
		return e.dialError(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(rsp.Body, 64<<10))
		return fmt.Errorf("hostagent: %s %s : statut %d", e.socket, path, rsp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(rsp.Body, max+1))
	if err != nil {
		return fmt.Errorf("hostagent: %s %s : %w", e.socket, path, err)
	}
	if int64(len(body)) > max {
		return fmt.Errorf("hostagent: %s %s : réponse de plus de %d octets", e.socket, path, max)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("hostagent: %s %s : réponse illisible : %w", e.socket, path, err)
	}
	return nil
}

func (e *SocketEngine) dialError(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" && strings.Contains(op.Err.Error(), "no such file or directory") {
		return fmt.Errorf("%w : %s", ErrEngineAbsent, e.socket)
	}
	return fmt.Errorf("hostagent: %s : %w", e.socket, err)
}

// detect lit /version : Podman s'y nomme parmi les composants.
func (e *SocketEngine) detect(ctx context.Context) error {
	var v struct {
		Components []struct{ Name string } `json:"Components"`
		Platform   struct{ Name string }   `json:"Platform"`
	}
	if err := e.get(ctx, "/version", maxEngineInspect, &v); err != nil {
		return err
	}
	e.name = EngineDocker
	for _, c := range append(v.Components, struct{ Name string }{v.Platform.Name}) {
		if strings.Contains(strings.ToLower(c.Name), "podman") {
			e.name = EnginePodman
		}
	}
	return nil
}

// Containers liste les conteneurs en cours d'exécution, avec leur date de démarrage.
func (e *SocketEngine) Containers(ctx context.Context) ([]Container, error) {
	if err := e.detect(ctx); err != nil {
		return nil, err
	}
	var list []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		Labels  map[string]string `json:"Labels"`
		State   string            `json:"State"`
	}
	// Sans « all », l'API ne renvoie que les conteneurs en cours d'exécution.
	if err := e.get(ctx, "/containers/json", maxEngineList, &list); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(list))
	for _, c := range list {
		if c.State != "" && c.State != "running" {
			continue
		}
		names := make([]string, 0, len(c.Names))
		for _, n := range c.Names {
			names = append(names, strings.TrimPrefix(n, "/"))
		}
		ct := Container{ID: c.ID, Names: names, Image: c.Image, ImageID: normalizeImageID(c.ImageID), Labels: c.Labels}
		var inspect struct {
			State struct {
				StartedAt string `json:"StartedAt"`
			} `json:"State"`
		}
		if err := e.get(ctx, "/containers/"+url.PathEscape(c.ID)+"/json", maxEngineInspect, &inspect); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil && t.Year() > 1 {
			ct.StartedAt = t.UTC()
		}
		out = append(out, ct)
	}
	return out, nil
}

// normalizeImageID écrit un identifiant d'image sous la forme sha256:<64 hex> (Podman le
// donne parfois sans préfixe) ; une autre forme est rendue telle quelle et sera écartée.
func normalizeImageID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) == 64 && !strings.ContainsFunc(id, func(r rune) bool { return !strings.ContainsRune("0123456789abcdef", r) }) {
		return "sha256:" + id
	}
	return id
}

// ExportImage écrit l'image au format docker-archive dans w (docker save), max octets au
// plus.
func (e *SocketEngine) ExportImage(ctx context.Context, imageID string, w io.Writer, max int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/images/"+url.PathEscape(imageID)+"/get", nil)
	if err != nil {
		return err
	}
	rsp, err := e.client.Do(req)
	if err != nil {
		return e.dialError(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("hostagent: export de l'image %s : statut %d", imageID, rsp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(rsp.Body, max+1))
	if err != nil {
		return fmt.Errorf("hostagent: export de l'image %s : %w", imageID, err)
	}
	if n > max {
		return ErrImageTooLarge
	}
	return nil
}

// Engines renvoie les moteurs à interroger selon la configuration : aucun si l'inventaire
// des conteneurs est désactivé (l'agent n'ouvre alors aucune socket), les sockets
// configurées, sinon DefaultSockets.
func Engines(c Containers) []ContainerEngine {
	if !c.Enabled {
		return nil
	}
	sockets := c.Sockets
	if len(sockets) == 0 {
		sockets = DefaultSockets
	}
	out := make([]ContainerEngine, 0, len(sockets))
	for _, s := range sockets {
		out = append(out, NewSocketEngine(s, c.Timeout))
	}
	return out
}
