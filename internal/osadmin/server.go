// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package osadmin is the :8443 appliance admin (spec 2, Sections 2.6 and
// 2.7): the static admin pages and the Connect API of
// proto/sneakers/appliance/osadmin/v1, the SSH-attested sign-in, the
// sessions, CSRF, roles, step-up and the OS audit entries for every
// action. Each method's Rule (role, step-up, audit action) is read from the
// proto descriptor, so a method without one is refused.
package osadmin

import (
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// CookieName is the session cookie. The __Host- prefix makes the browser
// insist on Secure, Path=/ and no Domain (host-only).
const CookieName = "__Host-osadmin-session"

// CSRFHeader carries the session's CSRF token on every call that changes
// something.
const CSRFHeader = "X-CSRF-Token"

// NotAvailable is what a service without a backend on this box answers.
const NotAvailable = "Not available in this release"

// Paths are where osadmin reads and writes on the state volume.
type Paths struct {
	// State is the state volume's root, /var/lib/sneakers on the box.
	State string
}

// SetupDir holds the setup markers.
func (p Paths) SetupDir() string { return filepath.Join(p.State, "setup") }

// EscrowDir holds the escrow files.
func (p Paths) EscrowDir() string { return filepath.Join(p.State, "backup", "escrow") }

// SSHDir holds the host keys.
func (p Paths) SSHDir() string { return filepath.Join(p.State, "ssh") }

// OwnDir is sneakers-osadmin's own directory, owned by the osadmin user:
// the :8443 certificate and its key.
func (p Paths) OwnDir() string { return filepath.Join(p.State, "osadmin") }

// APIDir is the API's files, root's (accessd runs the API): the disk
// samples, the update policy, history and uploads.
func (p Paths) APIDir() string { return filepath.Join(p.State, "osadmin-api") }

// Options wire the server to the store, the log and the daemons it calls.
type Options struct {
	Access     *access.Store
	Audit      *osaudit.Log
	Clock      clock.Clock
	KeyCustody initv1connect.KeyCustodyServiceClient
	Image      initv1connect.ImageServiceClient
	Power      initv1connect.PowerServiceClient
	Network    netdv1connect.NetworkServiceClient
	Paths      Paths
	// Cert describes :8443's own certificate, for Status. When CertDir is
	// set, the certificate there is read instead, on every Status.
	Cert    CertInfo
	CertDir string
	// Upgrade configures the update flows.
	Upgrade UpgradeOptions
	// Elevation is the one-time root shells; nil answers Not available.
	Elevation *elevation.Service
	// Shells is the admins' SSH logins to the closed shell
	// (sshsession.Proc on the box); nil lists none.
	Shells Shells
	// Assets are the static admin pages; nil serves a short notice.
	Assets fs.FS
	Logger log.Logger
}

// Server is the appliance admin.
type Server struct {
	o        Options
	logins   *weblogin.Manager
	sessions *weblogin.Sessions
	certMu   sync.Mutex
	resets   resets
	upgrades upgrades
}

// New returns a server.
func New(o Options) *Server {
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	return &Server{o: o, logins: weblogin.New(o.Clock), sessions: weblogin.NewSessions(o.Clock)}
}

// Handler is the whole :8443 handler in one process: the API, the static
// pages and the security headers. On the box sneakers-osadmin serves the
// pages and forwards the API to accessd, which serves APIHandler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	mux.Handle("/", StaticHandler(s.o.Assets))
	return SecurityHeaders(mux)
}

// APIHandler is the Connect API, the audit export and the upload. The
// caller's address is the request's RemoteAddr: accessd sets it from what
// sneakers-osadmin forwards.
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return mux
}

func (s *Server) routes(mux *http.ServeMux) {
	opts := connect.WithInterceptors(s.interceptor())
	mux.Handle(osadminv1connect.NewSignInServiceHandler(&signIn{s: s}, opts))
	mux.Handle(osadminv1connect.NewStatusServiceHandler(&status{s: s}, opts))
	mux.Handle(osadminv1connect.NewSetupServiceHandler(&setup{s: s}, opts))
	mux.Handle(osadminv1connect.NewAccessServiceHandler(&accessSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewNetworkServiceHandler(&networkSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewAuditServiceHandler(&audit{s: s}, opts))
	mux.Handle(osadminv1connect.NewPowerServiceHandler(&power{s: s}, opts))
	mux.Handle(osadminv1connect.NewElevationServiceHandler(&elevationSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewTlsServiceHandler(osadminv1connect.UnimplementedTlsServiceHandler{}, opts))
	mux.Handle(osadminv1connect.NewMcpServiceHandler(osadminv1connect.UnimplementedMcpServiceHandler{}, opts))
	mux.Handle(osadminv1connect.NewBackupServiceHandler(osadminv1connect.UnimplementedBackupServiceHandler{}, opts))
	mux.Handle(osadminv1connect.NewUpgradeServiceHandler(&upgradeSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewModulesServiceHandler(osadminv1connect.UnimplementedModulesServiceHandler{}, opts))
	mux.HandleFunc("GET /export/audit-log", s.exportAudit)
	mux.HandleFunc("POST /upload", s.handleUpload)
}

// Handlers are the API's handlers, for accessd's local API to run with
// RunLocal.
type Handlers struct {
	Status    osadminv1connect.StatusServiceHandler
	Setup     osadminv1connect.SetupServiceHandler
	Access    osadminv1connect.AccessServiceHandler
	Network   osadminv1connect.NetworkServiceHandler
	Elevation osadminv1connect.ElevationServiceHandler
}

// Handlers returns the handlers.
func (s *Server) Handlers() Handlers {
	return Handlers{
		Status: &status{s: s}, Setup: &setup{s: s}, Access: &accessSvc{s: s}, Network: &networkSvc{s: s},
		Elevation: &elevationSvc{s: s},
	}
}

// LocalHandler is LocalService, which accessd serves on access.sock to the
// closed shell and the console. Its listener must set the peer
// (initapi.PeerListener and initapi.PeerContext), and only root and admin
// uids may reach it.
func (s *Server) LocalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(osadminv1connect.NewLocalServiceHandler(&local{s: s}))
	return mux
}

// SecurityHeaders sets :8443's headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// StaticHandler serves the static pages in assets, falling back to
// index.html for the pages' own routes; nil assets serve a short notice.
func StaticHandler(assets fs.FS) http.Handler {
	if assets == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("The appliance admin pages aren't installed on this box. The API is available.\n"))
		})
	}
	files := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		if _, err := fs.Stat(assets, name); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			files.ServeHTTP(w, r2)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// SetCert updates the certificate Status describes, after a rebind.
func (s *Server) SetCert(c CertInfo) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	s.o.Cert = c
}

func (s *Server) cert() CertInfo {
	if s.o.CertDir != "" {
		info, err := ReadCertInfo(s.o.CertDir)
		if err != nil {
			s.o.Logger.Warn("osadmin: the :8443 certificate can't be read", log.F("error", err.Error()))
		}
		return info
	}
	s.certMu.Lock()
	defer s.certMu.Unlock()
	return s.o.Cert
}

// Sessions is the live session table (the console and Power show it).
func (s *Server) Sessions() *weblogin.Sessions { return s.sessions }
