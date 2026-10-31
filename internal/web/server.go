package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// Timeouts règle les délais des serveurs et l'arrêt propre.
type Timeouts struct {
	ReadHeader, Read, Write, Idle time.Duration
	// Shutdown est le délai laissé aux requêtes en cours après l'annulation de Run.
	Shutdown time.Duration
}

// ServerOptions paramètre NewServer.
type ServerOptions struct {
	PublicAddr     string
	ManagementAddr string
	Public         http.Handler
	Management     http.Handler
	// TLS active le TLS natif de l'écoute publique ; nil : HTTP derrière un mandataire.
	TLS      *tls.Config
	Timeouts Timeouts
	Logger   *slog.Logger
	// OnShutdown est appelé au début de l'arrêt (Readiness.Drain).
	OnShutdown func()
}

// Server sert l'interface publique et l'écoute de gestion.
type Server struct {
	opts       ServerOptions
	public     *http.Server
	management *http.Server
	publicLn   net.Listener
	mgmtLn     net.Listener
}

// NewServer prépare les deux serveurs HTTP.
func NewServer(o ServerOptions) *Server {
	newHTTP := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler:           h,
			ReadHeaderTimeout: o.Timeouts.ReadHeader,
			ReadTimeout:       o.Timeouts.Read,
			WriteTimeout:      o.Timeouts.Write,
			IdleTimeout:       o.Timeouts.Idle,
			ErrorLog:          slog.NewLogLogger(o.Logger.Handler(), slog.LevelWarn),
		}
	}
	s := &Server{opts: o, public: newHTTP(o.Public), management: newHTTP(o.Management)}
	s.public.TLSConfig = o.TLS
	return s
}

// Listen ouvre les deux écoutes : une adresse occupée échoue avant tout service.
func (s *Server) Listen() error {
	var err error
	if s.publicLn, err = net.Listen("tcp", s.opts.PublicAddr); err != nil {
		return fmt.Errorf("web: écoute publique %s : %w", s.opts.PublicAddr, err)
	}
	if s.mgmtLn, err = net.Listen("tcp", s.opts.ManagementAddr); err != nil {
		_ = s.publicLn.Close()
		return fmt.Errorf("web: écoute de gestion %s : %w", s.opts.ManagementAddr, err)
	}
	return nil
}

// PublicAddr renvoie l'adresse effective de l'écoute publique (après Listen).
func (s *Server) PublicAddr() string { return s.publicLn.Addr().String() }

// ManagementAddr renvoie l'adresse effective de l'écoute de gestion (après Listen).
func (s *Server) ManagementAddr() string { return s.mgmtLn.Addr().String() }

// Run sert jusqu'à l'annulation de ctx, puis arrête proprement : plus de nouvelles
// connexions, les requêtes en cours ont Timeouts.Shutdown pour finir, au-delà les
// connexions sont fermées et Run renvoie une erreur.
func (s *Server) Run(ctx context.Context) error {
	if s.publicLn == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	useTLS := s.opts.TLS != nil
	errs := make(chan error, 2)
	go func() {
		var err error
		if useTLS {
			err = s.public.ServeTLS(s.publicLn, "", "")
		} else {
			err = s.public.Serve(s.publicLn)
		}
		errs <- err
	}()
	go func() { errs <- s.management.Serve(s.mgmtLn) }()
	s.opts.Logger.Info("serveur démarré", "public", s.PublicAddr(), "management", s.ManagementAddr(), "tls", useTLS)

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
	}
	if s.opts.OnShutdown != nil {
		s.opts.OnShutdown()
	}
	s.opts.Logger.Info("arrêt du serveur", "grace", s.opts.Timeouts.Shutdown.String())
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.opts.Timeouts.Shutdown)
	defer cancel()
	shutdownErr := errors.Join(s.public.Shutdown(sctx), s.management.Shutdown(sctx))
	if shutdownErr != nil {
		_ = s.public.Close()
		_ = s.management.Close()
		shutdownErr = fmt.Errorf("web: arrêt forcé après %s : %w", s.opts.Timeouts.Shutdown, shutdownErr)
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	if serveErr != nil {
		serveErr = fmt.Errorf("web: %w", serveErr)
	}
	return errors.Join(serveErr, shutdownErr)
}

// TLSConfig charge le certificat de l'écoute publique et, si clientCA est donné,
// l'autorité des certificats clients des agents : un certificat présenté est vérifié,
// son absence reste permise ici : l'interface web n'en demande pas, et l'API des agents
// refuse une requête sans certificat vérifié (api.AgentOptions.RequireClientCert).
func TLSConfig(certFile, keyFile, clientCA string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls.cert_file / tls.key_file : %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, fmt.Errorf("tls.client_ca_file : %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tls.client_ca_file : aucun certificat PEM")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}
