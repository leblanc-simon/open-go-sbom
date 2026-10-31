package render

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// Graphiques SVG produits côté serveur (§ 14 de l'architecture) : ce fichier calcule la
// géométrie, les gabarits partials/charts.html la dessinent. Aucun style ni script en
// ligne (CSP) : couleurs et traits viennent des classes CSS ; les valeurs exactes se
// lisent au survol par <title> et dans le tableau de données qui accompagne chaque
// graphique.
//
//	{{template "chart_line" .Chart}}   courbe d'une série (render.LineChart)
//	{{template "chart_bars" .Bars}}    barres horizontales en tableau (render.BarChart)

// Dimensions de la zone de dessin d'une courbe (unités du viewBox, étirées à la largeur
// du conteneur : preserveAspectRatio="none", traits non déformés par vector-effect).
const (
	LineWidth  = 600
	LineHeight = 52
	// lineTop et lineBottom bornent la courbe dans la hauteur.
	lineTop    = 6
	lineBottom = 50
)

// ChartPoint est un point d'une série temporelle.
type ChartPoint struct {
	At    time.Time
	Value float64
}

// ChartHit est la zone de survol d'un point : un rectangle pleine hauteur qui porte la date
// et la valeur dans son <title>.
type ChartHit struct {
	X, W  string
	Date  string // AAAA-MM-JJ, en UTC
	Value float64
}

// LineChart est une courbe prête à dessiner.
type LineChart struct {
	// ID préfixe les identifiants du titre et de la description (uniques dans la page).
	ID string
	// Class ajoute des classes au <svg> (« chart--critical » pour la couleur d'une
	// sévérité).
	Class string
	// TitleKey et DescKey sont les clés de traduction du titre et de la description,
	// TitleArgs et DescArgs leurs paramètres.
	TitleKey  string
	TitleArgs map[string]any
	DescKey   string
	DescArgs  map[string]any

	Width, Height int
	Baseline      int
	// Line : attribut points de la polyline ; Area : tracé de l'aire sous la courbe (vide
	// pour moins de deux points).
	Line string
	Area string
	// DotX, DotY : dernier point, marqué même quand il est seul.
	DotX, DotY string
	Hits       []ChartHit
	// Max est la plus grande valeur, sommet de l'échelle propre à la courbe.
	Max float64
}

// NewLineChart place les points (triés par date) sur l'intervalle [from, to] : abscisse
// proportionnelle au temps, si bien qu'un jour sans statistique reste visible comme un
// segment plus long ; ordonnée de zéro (bas) au maximum de la série (haut).
func NewLineChart(from, to time.Time, points []ChartPoint) LineChart {
	c := LineChart{Width: LineWidth, Height: LineHeight, Baseline: lineBottom}
	if len(points) == 0 {
		return c
	}
	for _, p := range points {
		c.Max = math.Max(c.Max, p.Value)
	}
	span := to.Sub(from).Seconds()
	xs := make([]float64, len(points))
	ys := make([]float64, len(points))
	coords := make([]string, len(points))
	for i, p := range points {
		xs[i] = LineWidth
		if span > 0 {
			xs[i] = math.Min(math.Max(p.At.Sub(from).Seconds()/span, 0), 1) * LineWidth
		}
		ys[i] = lineBottom
		if c.Max > 0 {
			ys[i] = lineBottom - p.Value/c.Max*(lineBottom-lineTop)
		}
		coords[i] = num(xs[i]) + "," + num(ys[i])
	}
	c.Line = strings.Join(coords, " ")
	if len(points) > 1 {
		c.Area = "M" + num(xs[0]) + "," + num(lineBottom) + " L" + c.Line + " L" + num(xs[len(xs)-1]) + "," + num(lineBottom) + " Z"
	}
	c.DotX, c.DotY = num(xs[len(xs)-1]), num(ys[len(ys)-1])
	for i, p := range points {
		left, right := 0.0, float64(LineWidth)
		if i > 0 {
			left = (xs[i-1] + xs[i]) / 2
		}
		if i < len(points)-1 {
			right = (xs[i] + xs[i+1]) / 2
		}
		u := p.At.UTC()
		c.Hits = append(c.Hits, ChartHit{X: num(left), W: num(right - left), Date: u.Format(time.DateOnly), Value: p.Value})
	}
	return c
}

// num écrit une coordonnée au dixième, sans zéro inutile : des SVG stables et compacts.
func num(v float64) string {
	return strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
}

// Bar est une ligne d'un graphique à barres.
type Bar struct {
	// Class et LabelKey : classes et clé de traduction du libellé (« sev sev--high »,
	// « severity.high ») ; le libellé est toujours écrit, jamais porté par la seule
	// couleur.
	Class    string
	LabelKey string
	// Value est la valeur, ValueKey la clé de traduction qui l'affiche avec son unité
	// (paramètre Value, déjà localisé) ; Missing marque une ligne sans donnée.
	Value    float64
	ValueKey string
	Missing  bool
	// Width est la longueur de la barre, de 0 à 100 (proportion du maximum).
	Width int
}

// BarChart est un graphique à barres horizontales rendu comme un tableau : chaque ligne
// porte son libellé, sa barre (SVG décoratif) et sa valeur exacte, si bien que le tableau
// est lui-même la donnée équivalente du graphique.
type BarChart struct {
	ID       string
	TitleKey string
	DescKey  string
	DescArgs map[string]any
	Rows     []Bar
}

// NewBarChart calcule la longueur des barres, proportionnelle à la plus grande valeur.
func NewBarChart(rows []Bar) []Bar {
	maxValue := 0.0
	for _, r := range rows {
		if !r.Missing {
			maxValue = math.Max(maxValue, r.Value)
		}
	}
	out := make([]Bar, len(rows))
	for i, r := range rows {
		r.Width = 0
		if !r.Missing && maxValue > 0 {
			r.Width = int(math.Round(math.Max(r.Value, 0) / maxValue * 100))
		}
		out[i] = r
	}
	return out
}
