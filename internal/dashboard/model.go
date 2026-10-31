package dashboard

import (
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/vuln"
)

// Period est la fenêtre des séries et des délais de correction, en jours.
type Period int

// Périodes proposées.
const (
	Period30  Period = 30
	Period90  Period = 90
	Period365 Period = 365
	// DefaultPeriod est la période par défaut : la tendance sur 90 jours de la fiche.
	DefaultPeriod = Period90
)

// Periods renvoie les périodes proposées, de la plus courte à la plus longue.
func Periods() []Period { return []Period{Period30, Period90, Period365} }

// ParsePeriod lit une période (« 90 ») ; toute autre valeur donne DefaultPeriod.
func ParsePeriod(s string) Period {
	n, err := strconv.Atoi(s)
	if err != nil {
		return DefaultPeriod
	}
	for _, p := range Periods() {
		if Period(n) == p {
			return p
		}
	}
	return DefaultPeriod
}

// Step est l'écart en jours entre deux points d'une série : un point par jour jusqu'à
// 90 jours, un par semaine au-delà, pour garder un graphique et un tableau lisibles.
func (p Period) Step() int {
	if p > Period90 {
		return 7
	}
	return 1
}

// WeekAgo est l'écart de la variation affichée sous chaque décompte.
const WeekAgo = 7

// TopN borne les listes du tableau de bord (projets exposés, composants, agents muets).
const TopN = 5

// Counts décompte des constats ouverts.
type Counts struct {
	BySeverity map[vuln.Severity]int
	KEV        int // constats ouverts marqués KEV
}

// Of renvoie le nombre de constats ouverts d'une sévérité (pour les gabarits).
func (c Counts) Of(s vuln.Severity) int { return c.BySeverity[s] }

// Total renvoie le nombre de constats ouverts, toutes sévérités.
func (c Counts) Total() int {
	n := 0
	for _, v := range c.BySeverity {
		n += v
	}
	return n
}

func newCounts() Counts { return Counts{BySeverity: map[vuln.Severity]int{}} }

// Point est l'état d'un jour d'une série (UTC, minuit).
type Point struct {
	Day  time.Time
	Open Counts
}

// FixTime est le délai médian de correction d'une sévérité sur la période.
type FixTime struct {
	Fixed  int           // constats résolus pendant la période
	Median time.Duration // significatif si Fixed > 0
}

// Summary réunit les indicateurs communs au tableau de bord et à la fiche projet.
type Summary struct {
	At     time.Time // instant de la lecture (UTC)
	Period Period
	Open   Counts
	// KEVVulns et KEVProjects : vulnérabilités KEV distinctes ouvertes, et projets qui en
	// portent.
	KEVVulns    int
	KEVProjects int
	// WeekAgo est l'état enregistré il y a WeekAgo jours ; nil sans statistique ce
	// jour-là.
	WeekAgo *Counts
	// Trend va du plus ancien au plus récent ; son dernier point est l'état courant.
	Trend    []Point
	FixTimes map[vuln.Severity]FixTime
	// LastAnalysis est la dernière analyse de vulnérabilités d'une référence.
	LastAnalysis *time.Time
}

// Org est le tableau de bord d'une organisation.
type Org struct {
	Summary
	// Projects compte les projets actifs par nature.
	Projects map[project.Kind]int
	Exposed  []ExposedProject
	// Widespread : familles de composants vulnérables les plus répandues.
	Widespread []Component
	// SilentAgents compte les agents muets ; Silent donne les TopN plus anciens.
	SilentAgents int
	Silent       []agent.Agent
}

// ProjectCount renvoie le nombre de projets actifs, toutes natures.
func (o Org) ProjectCount() int {
	n := 0
	for _, v := range o.Projects {
		n += v
	}
	return n
}

// ExposedProject est un projet aux constats ouverts.
type ExposedProject struct {
	ID      uuid.UUID
	Slug    string
	Name    string
	Kind    project.Kind
	MaxRisk float64
	Open    Counts
}

// Component est une famille de composants (purl_base) aux constats ouverts.
type Component struct {
	// ID désigne l'une des versions vulnérables (fiche composant, qui montre la famille).
	ID       uuid.UUID
	PURLBase string
	Name     string
	Projects int
	// Versions : les premières versions vulnérables (VersionsShown au plus), triées ;
	// VersionCount : leur nombre total.
	Versions     []string
	VersionCount int
	Worst        vuln.Severity
	KEV          bool
}

// VersionsShown borne les versions affichées d'une famille de composants.
const VersionsShown = 3
