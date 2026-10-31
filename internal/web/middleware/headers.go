package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// CSPInterface est la politique de sécurité du contenu de l'interface (§ 14) : aucun
// script ni style en ligne, rien hors de l'origine.
const CSPInterface = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"frame-ancestors 'none'; form-action 'self'; base-uri 'none'"

// CSPAPI est la politique des réponses d'API : elles ne sont jamais rendues comme pages.
const CSPAPI = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

// permissionsPolicy coupe les fonctions du navigateur dont l'interface n'a pas besoin.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
	"encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), " +
	"microphone=(), midi=(), payment=(), publickey-credentials-get=(), screen-wake-lock=(), " +
	"usb=(), xr-spatial-tracking=()"

// hstsValue : deux ans, sans includeSubDomains, qui engagerait d'autres services du domaine.
const hstsValue = "max-age=63072000"

// SecurityOptions paramètre SecurityHeaders.
type SecurityOptions struct {
	// CSP est la politique de sécurité du contenu (CSPInterface, CSPAPI).
	CSP string
	// HTTPS indique si la requête est arrivée en HTTPS : Strict-Transport-Security n'est
	// envoyé qu'alors (voir TLSDetector).
	HTTPS func(*http.Request) bool
	// NoStore interdit la mise en cache (pages qui porteront des données de compte).
	NoStore bool
}

// SecurityHeaders pose les en-têtes de sécurité sur toutes les réponses du groupe, avant
// le handler : une page d'erreur ou une panique récupérée les porte aussi.
func SecurityHeaders(opts SecurityOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", opts.CSP)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Permissions-Policy", permissionsPolicy)
			h.Set("X-Frame-Options", "DENY")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			if opts.HTTPS != nil && opts.HTTPS(r) {
				h.Set("Strict-Transport-Security", hstsValue)
			}
			if opts.NoStore {
				h.Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TrustedProxies est l'ensemble des mandataires inverses de confiance (web.trusted_proxies).
type TrustedProxies []netip.Prefix

// ParseTrustedProxies lit une liste de CIDR.
func ParseTrustedProxies(cidrs []string) (TrustedProxies, error) {
	out := make(TrustedProxies, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Trusts indique si la connexion directe vient d'un mandataire de confiance.
func (t TrustedProxies) Trusts(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range t {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// TLSDetector renvoie une fonction qui dit si une requête est arrivée en HTTPS : TLS natif,
// ou X-Forwarded-Proto: https posé par un mandataire de confiance. Un client direct ne peut
// pas se déclarer en HTTPS.
func TLSDetector(proxies TrustedProxies) func(*http.Request) bool {
	return func(r *http.Request) bool {
		if r.TLS != nil {
			return true
		}
		return proxies.Trusts(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
}
