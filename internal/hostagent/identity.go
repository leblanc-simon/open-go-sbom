package hostagent

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Étiquettes Compose lues pour l'identité d'un conteneur. docker compose et
// podman-compose posent les étiquettes com.docker.compose.* ; podman-compose pose aussi
// io.podman.compose.project.
const (
	LabelComposeProject       = "com.docker.compose.project"
	LabelComposeService       = "com.docker.compose.service"
	LabelPodmanComposeProject = "io.podman.compose.project"
)

// Les noms de projets et de services Compose et les noms de conteneurs commencent par
// une lettre ou un chiffre, puis n'ont que des lettres, chiffres, « _ », « . » et « - ».
var (
	composePart   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	containerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	imageIDForm   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Identity renvoie l'identité d'un conteneur dans son hôte, qui décide quand un
// conteneur recréé reste le même projet (décision du 1er novembre 2026) : le projet
// Compose et le service, « projet/service », quand les étiquettes Compose sont présentes
// (les répliques d'un service et ses conteneurs recréés forment un seul projet), sinon le
// nom du conteneur. ok est faux pour un conteneur sans nom utilisable, qui n'est pas
// inventorié. C'est la seule fonction qui en décide.
func Identity(c Container) (key string, compose bool, ok bool) {
	project := c.Labels[LabelComposeProject]
	if project == "" {
		project = c.Labels[LabelPodmanComposeProject]
	}
	service := c.Labels[LabelComposeService]
	if composePart.MatchString(project) && composePart.MatchString(service) {
		return project + "/" + service, true, true
	}
	for _, n := range c.Names {
		if containerName.MatchString(n) {
			return n, false, true
		}
	}
	return "", false, false
}

// maxReportedNames borne les noms de conteneurs annoncés pour une identité.
const maxReportedNames = 16

// maxImageRef borne la référence d'image annoncée.
const maxImageRef = 255

// Workload réunit les conteneurs d'une identité sur un moteur : les répliques d'un
// service Compose, ou un conteneur seul. Son image est celle du conteneur démarré le
// plus récemment (une mise à jour en cours peut faire coexister deux images).
type Workload struct {
	Key            string
	Engine         ContainerEngine
	Names          []string
	Replicas       int
	Image          string
	ImageID        string
	ComposeProject string
	ComposeService string
	StartedAt      time.Time
}

// Workloads regroupe par identité les conteneurs des moteurs, triés par identité. Une
// identité vue sur deux moteurs ne forme qu'un projet : le conteneur démarré le plus
// récemment l'emporte. skipped compte les conteneurs écartés (sans identité ou sans
// empreinte d'image lisible).
func Workloads(perEngine map[ContainerEngine][]Container) (out []Workload, skipped int) {
	type member struct {
		engine ContainerEngine
		c      Container
	}
	groups := map[string][]member{}
	for e, list := range perEngine {
		for _, c := range list {
			key, _, ok := Identity(c)
			if !ok || !imageIDForm.MatchString(c.ImageID) {
				skipped++
				continue
			}
			groups[key] = append(groups[key], member{e, c})
		}
	}
	for key, members := range groups {
		// Le plus récent d'abord ; à égalité, l'identifiant départage (ordre stable).
		slices.SortFunc(members, func(a, b member) int {
			return cmp.Or(b.c.StartedAt.Compare(a.c.StartedAt), strings.Compare(a.c.ID, b.c.ID))
		})
		head := members[0]
		w := Workload{Key: key, Engine: head.engine, Replicas: len(members), Image: clip(head.c.Image, maxImageRef),
			ImageID: head.c.ImageID, StartedAt: head.c.StartedAt}
		if w.Image == "" {
			w.Image = head.c.ImageID
		}
		if _, compose, _ := Identity(head.c); compose {
			w.ComposeProject, w.ComposeService, _ = strings.Cut(key, "/")
		}
		for _, m := range members {
			for _, n := range m.c.Names {
				if containerName.MatchString(n) && !slices.Contains(w.Names, n) {
					w.Names = append(w.Names, n)
				}
			}
		}
		slices.Sort(w.Names)
		if len(w.Names) > maxReportedNames {
			w.Names = w.Names[:maxReportedNames]
		}
		if len(w.Names) == 0 {
			// Une identité Compose dont aucun nom n'est lisible : le service le remplace.
			w.Names = []string{clip(strings.ReplaceAll(key, "/", "-"), 255)}
		}
		out = append(out, w)
	}
	slices.SortFunc(out, func(a, b Workload) int { return strings.Compare(a.Key, b.Key) })
	return out, skipped
}
