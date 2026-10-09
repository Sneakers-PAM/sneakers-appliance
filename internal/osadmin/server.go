// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package osadmin is the :8443 appliance admin (spec 2, Sections 2.4 to
// 2.7): the static admin pages and the Connect API of
// proto/sneakers/appliance/osadmin/v1, the setup stepper and its one-time
// codes, the password and TOTP sign-in with its lockout, the sessions,
// CSRF, roles, step-up, the issued SSH keys, the root-shell codes and the
// OS audit entries for every action. Each method's Rule (role, step-up, audit action) is read from the
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// CookieName is the session cookie. The __Host- prefix makes the browser
// insist on Secure, Path=/ and no Domain (host-only).
const CookieName = "__Host-osadmin-session"

// CodeCookieName is the cookie of a redeemed one-time code's session.
const CodeCookieName = "__Host-osadmin-code"

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
	// RootSource is where the running root came from (init's
	// SNEAKERS_ROOT_SOURCE): a root slot's label, or empty when unknown.
	RootSource string
	// BootID is the kernel's boot ID (/proc/sys/kernel/random/boot_id).
	// The reboot watchdog uses it to tell osadmin restarting from the box
	// rebooting; empty turns the watchdog off.
	BootID     string
	Access     *access.Store
	Audit      *osaudit.Log
	Clock      clock.Clock
	KeyCustody initv1connect.KeyCustodyServiceClient
	Image      initv1connect.ImageServiceClient
	Power      initv1connect.PowerServiceClient
	// Services restarts the product service after a product apply or
	// revert; nil can't.
	Services initv1connect.ServicesServiceClient
	// ProductUp tells how far the product has come up after that restart
	// (productup.Probe on the box). A product apply or revert follows it
	// as the steps after restarting, until the product answers on 443;
	// nil ends the apply at the restart.
	ProductUp ProductProbe
	Network   netdv1connect.NetworkServiceClient
	Paths     Paths
	// BoxStateFile is init's announcement of a reboot or a shutdown
	// (boxstate.File on the box), which GetPhase's state reports; empty
	// reads none.
	BoxStateFile string
	// Cert describes :8443's own certificate, for Status. When CertDir is
	// set, the certificate there is read instead, on every Status.
	Cert    CertInfo
	CertDir string
	// Certs is the certificate store behind TlsService; nil answers Not
	// available.
	Certs *certstore.Store
	// Upgrade configures the update flows.
	Upgrade UpgradeOptions
	// Elevation is the root shells; nil answers Not available.
	Elevation *elevation.Service
	// CodeSealer seals the setup code (init's KeyCustody on the box). Nil
	// keeps it in memory only (tests).
	CodeSealer onetime.Sealer
	// RootKey is the box's root key and pepper. Required for setup,
	// sign-in and issued SSH keys.
	RootKey *rootkey.Key
	// Lockout is the shared lockout and throttling book. Required.
	Lockout *lockout.Book
	// OnFirstAdmin runs once the first admin exists: accessd starts sshd.
	OnFirstAdmin func()
	// OnConsoleChange runs whenever what the console shows changes.
	OnConsoleChange func()
	// Shells is the admins' SSH logins to the closed shell
	// (sshsession.Proc on the box); nil lists none.
	Shells Shells
	// Assets are the static admin pages; nil serves a short notice.
	Assets fs.FS
	// Switches turn the installed product's switches (its MCP) on and
	// off; nil answers the MCP page with no product.
	Switches *productswitch.Switches
	// ImportChown hands the import directory's files to the import Job's
	// user; nil is os.Chown (tests run unprivileged).
	ImportChown func(path string, uid, gid int) error
	// Exposed reads the installed product's exposed values as the
	// appliance's own service account (kubeapi.Client on the box); nil
	// reads none.
	Exposed ExposedReader
	Logger  log.Logger
}

// Server is the appliance admin.
type Server struct {
	o        Options
	sessions *weblogin.Sessions
	codes    *onetime.Codes
	creds    credentialFlows
	certMu   sync.Mutex
	resets   resets
	upgrades upgrades
	mirror   mirrorCheck
	checks   checks
	progress progress
	// revertMu guards revertAudited, the last network change whose revert
	// is in the audit, so a timer and a late check don't write it twice.
	revertMu      sync.Mutex
	revertAudited string
}

// New returns a server.
func New(o Options) *Server {
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	s := &Server{o: o, sessions: weblogin.NewSessions(o.Clock)}
	s.codes = onetime.NewCodes(o.Clock, s.consoleChanged, o.CodeSealer, o.Logger)
	s.creds.init()
	if s.FirstAdminDone() {
		s.codes.ConsumeSetup()
	}
	return s
}

// Handler is the whole :8443 handler in one process: the API, the static
// pages and the security headers. On the box sneakers-osadmin serves the
// pages and forwards the API to accessd, which serves APIHandler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	mux.Handle("/", PagesHandler(s.o.Assets, func(*http.Request) (string, error) { return s.Phase(), nil }, s.o.Logger))
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
	mux.Handle(osadminv1connect.NewRootShellServiceHandler(&rootShellSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewTlsServiceHandler(&tlsSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewMcpServiceHandler(&mcpSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewImportServiceHandler(&importSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewBackupServiceHandler(osadminv1connect.UnimplementedBackupServiceHandler{}, opts))
	mux.Handle(osadminv1connect.NewUpgradeServiceHandler(&upgradeSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewProductServiceHandler(&productSvc{s: s}, opts))
	mux.Handle(osadminv1connect.NewModulesServiceHandler(osadminv1connect.UnimplementedModulesServiceHandler{}, opts))
	mux.HandleFunc("GET /export/audit-log", s.exportAudit)
	mux.HandleFunc("POST /upload", s.handleUpload)
	mux.HandleFunc("POST /import/upload", s.handleImportUpload)
}

// Handlers are the API's handlers, for accessd's local API to run with
// RunLocal.
type Handlers struct {
	Status    osadminv1connect.StatusServiceHandler
	Setup     osadminv1connect.SetupServiceHandler
	Access    osadminv1connect.AccessServiceHandler
	Network   osadminv1connect.NetworkServiceHandler
	Elevation osadminv1connect.ElevationServiceHandler
	Product   osadminv1connect.ProductServiceHandler
}

// Handlers returns the handlers.
func (s *Server) Handlers() Handlers {
	return Handlers{
		Status: &status{s: s}, Setup: &setup{s: s}, Access: &accessSvc{s: s}, Network: &networkSvc{s: s},
		Elevation: &elevationSvc{s: s}, Product: &productSvc{s: s},
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

func (s *Server) consoleChanged() {
	if s.o.OnConsoleChange != nil {
		s.o.OnConsoleChange()
	}
}
