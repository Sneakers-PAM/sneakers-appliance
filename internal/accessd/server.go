// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package accessd is sneakers-accessd (spec 2, Section 3.1): the root
// service that owns the access store, the sign-in codes and sessions, the
// OS audit log, and the accounts and sshd files rendered from the store.
// It serves /run/sneakers/access.sock, where the peer uid (SO_PEERCRED) is
// the caller's identity:
//
//   - root is the console: every method of sneakers.appliance.access.v1,
//     as an owner named console, and osadmin.v1's LocalService;
//   - an admin uid is a closed-shell login: the access.v1 methods the shell
//     needs, as that admin with that admin's role, and LocalService;
//   - the osadmin uid is sneakers-osadmin: the :8443 API of
//     sneakers.appliance.osadmin.v1, where every call carries the
//     signed-in admin's session and accessd checks it and the role, and
//     access.v1's BindingService.
//
// Anyone else is refused before a byte is read.
package accessd

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// Paths are where accessd renders under /run.
type Paths struct {
	// Run is /run/sneakers on the box.
	Run string
	// SSHD is the pinned sshd that checks every rendered config (sshd -t);
	// empty skips the check (tests).
	SSHD string
}

// AccountsDir holds passwd, group and shadow (/etc links into it).
func (p Paths) AccountsDir() string { return filepath.Join(p.Run, "accounts") }

// HomesDir holds the empty login homes.
func (p Paths) HomesDir() string { return filepath.Join(p.Run, "home") }

// SSHDir is sshd's rendered configuration.
func (p Paths) SSHDir() string { return filepath.Join(p.Run, "ssh") }

// SSHDPidFile is where sshd writes its pid.
func (p Paths) SSHDPidFile() string { return filepath.Join(p.Run, "sshd.pid") }

// Options wire accessd.
type Options struct {
	// Network is netd's API, for the binding, the relayed network calls
	// and sshd's listen addresses.
	Network netdv1connect.NetworkServiceClient
	Paths   Paths
	// StatusFile is where the last status is kept, readable by the shell
	// and sneakers-osadmin when accessd is down.
	StatusFile string
	// Elevation is the one-time root shells; nil answers Not available.
	Elevation *elevation.Service
	// Enrolment is the SSH key enrolment window; nil answers Not
	// available.
	Enrolment *enrol.Service
	// HostKeyDir is where the SSH host keys live
	// (/var/lib/sneakers/ssh); empty never makes them.
	HostKeyDir string
	// AuditDir is the OS audit log's directory, where the session
	// recordings are.
	AuditDir string
	Logger   log.Logger
}

// Server is accessd.
type Server struct {
	o     Options
	store *access.Store
	api   *osadmin.Server
	h     osadmin.Handlers

	renderMu sync.Mutex
}

// New returns accessd; Attach gives it the store and the API before it
// serves.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	return &Server{o: o}
}

// Attach wires the store (opened with Changed as its OnChange) and the
// :8443 API's backend, and renders the files from the store's current
// version.
func (s *Server) Attach(store *access.Store, api *osadmin.Server) {
	s.store, s.api, s.h = store, api, api.Handlers()
	s.Changed(store.Read())
}

// nobodyUID is the overflow uid, never an admin.
const nobodyUID = 65534

// PeerAllowed is access.sock's peer rule: root, the osadmin uid, the
// enrol uid, or a uid in the admin range (which must also belong to an
// admin, checked per call).
func PeerAllowed(uid uint32) bool {
	return uid == 0 || uid == accounts.OsadminUID || uid == accounts.EnrolUID || (uid >= access.FirstUID && uid < nobodyUID)
}

// Handler routes each request by its peer's class.
func (s *Server) Handler() http.Handler {
	local := http.NewServeMux()
	local.Handle(accessv1connect.NewAccessServiceHandler(&accessH{s: s}))
	local.Handle(accessv1connect.NewNetworkServiceHandler(&networkH{s: s}))
	local.Handle(accessv1connect.NewSetupServiceHandler(&setupH{s: s}))
	local.Handle(accessv1connect.NewElevationServiceHandler(&elevationH{s: s}))
	local.Handle(accessv1connect.NewEnrolmentServiceHandler(&enrolmentH{s: s}))
	local.Handle("/"+osadminv1connect.LocalServiceName+"/", s.api.LocalHandler())

	// The enrol uid is sneakers-enrol: the code and its key's state only.
	enrolMux := http.NewServeMux()
	enrolMux.Handle(accessv1connect.NewEnrolmentServiceHandler(&enrolmentH{s: s}))

	front := http.NewServeMux()
	front.Handle(accessv1connect.NewBindingServiceHandler(&bindingH{s: s}))
	front.Handle("/", s.api.APIHandler())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := initapi.PeerFrom(r.Context())
		switch {
		case !ok || !PeerAllowed(p.UID):
			s.o.Logger.Warn("accessd: a request without an allowed peer; refused", log.F("uid", p.UID))
			http.Error(w, "forbidden", http.StatusForbidden)
		case p.UID == accounts.OsadminUID:
			r2 := r.Clone(r.Context())
			r2.RemoteAddr = "unknown"
			if a, err := netip.ParseAddr(r.Header.Get(accessapi.ClientHeader)); err == nil {
				r2.RemoteAddr = a.String()
			}
			front.ServeHTTP(w, r2)
		case p.UID == accounts.EnrolUID:
			enrolMux.ServeHTTP(w, r)
		default:
			local.ServeHTTP(w, r)
		}
	})
}

// shellMethods are the access.v1 methods an admin uid may call: the
// closed shell's. Everything else is root's (the console and firstboot).
var shellMethods = map[string]bool{
	accessv1connect.AccessServiceGetStatusProcedure:                  true,
	accessv1connect.AccessServiceListAdminsProcedure:                 true,
	accessv1connect.AccessServiceAddAdminProcedure:                   true,
	accessv1connect.AccessServiceRemoveAdminProcedure:                true,
	accessv1connect.AccessServiceListKeysProcedure:                   true,
	accessv1connect.AccessServiceAddKeyProcedure:                     true,
	accessv1connect.AccessServiceRemoveKeyProcedure:                  true,
	accessv1connect.NetworkServiceGetNetworkProcedure:                true,
	accessv1connect.NetworkServiceSetNetworkProcedure:                true,
	accessv1connect.NetworkServiceConfirmNetworkProcedure:            true,
	accessv1connect.SetupServiceGetSetupProcedure:                    true,
	accessv1connect.SetupServiceSetRecoveryKeyProcedure:              true,
	accessv1connect.ElevationServiceRequestElevationProcedure:        true,
	accessv1connect.ElevationServiceListElevationsProcedure:          true,
	accessv1connect.ElevationServiceGetElevationCertificateProcedure: true,
}

// SetEnrolment gives accessd the enrolment window, which needs the store
// accessd renders from.
func (s *Server) SetEnrolment(e *enrol.Service) { s.o.Enrolment = e }

// Rerender renders the files that follow the store, the elevation
// principals and the enrolment window again: the elevation service's and
// the window's OnChange.
func (s *Server) Rerender() {
	if s.store != nil {
		s.Changed(s.store.Read())
	}
}

// Tick runs the minute's sweeps: expired elevation requests and
// certificates, lost sessions, and an idle enrolment window.
func (s *Server) Tick() {
	if s.o.Elevation != nil {
		s.o.Elevation.Sweep()
	}
	if s.o.Enrolment != nil {
		s.o.Enrolment.Sweep()
	}
}

// caller names a local call's caller from its peer uid. procedure is the
// access.v1 method, checked against the shell's list for an admin uid.
func (s *Server) caller(ctx context.Context, h http.Header, procedure string) (osadmin.Local, error) {
	p, ok := initapi.PeerFrom(ctx)
	if !ok {
		return osadmin.Local{}, connect.NewError(connect.CodePermissionDenied, errors.New("the caller's credentials are unknown"))
	}
	if p.UID == 0 {
		return osadmin.Local{Source: "console"}, nil
	}
	if !shellMethods[procedure] {
		s.o.Logger.Warn("accessd: an admin uid called a console method; refused", log.F("uid", p.UID), log.F("procedure", procedure))
		return osadmin.Local{}, refuse(codes.New(codes.AccessForbidden, "this is done on the console"))
	}
	st := s.store.Read()
	a, ok := st.AdminByUID(int(p.UID))
	if !ok {
		s.o.Logger.Warn("accessd: a uid in the admin range with no admin; refused", log.F("uid", p.UID))
		return osadmin.Local{}, refuse(codes.New(codes.AccessForbidden, "this login isn't an admin"))
	}
	return osadmin.Local{Admin: a.Name, KeyFP: h.Get(accessapi.KeyHeader), Source: h.Get(accessapi.SourceHeader)}, nil
}

// refuse is a refusal as the Connect error the shell reads.
func refuse(err error) error {
	return connect.NewError(connect.CodePermissionDenied, errors.New(codes.Describe(err)))
}
