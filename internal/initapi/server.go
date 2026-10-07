// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package initapi serves init's local API on /run/sneakers/init.sock
// (proto sneakers.appliance.init.v1) with Connect, which also speaks the
// gRPC protocol. Only root may connect; every connection's peer is checked
// with SO_PEERCRED before a request is read. PowerService is also served
// alone on /run/sneakers/power.sock for the closed shell's admin logins,
// and it answers only the :8443 API (sneakers-accessd) and the shell, told
// apart by the peer's executable.
package initapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// SocketPath is where the API listens.
const SocketPath = "/run/sneakers/init.sock"

// PowerSocketPath serves PowerService alone to the closed shell's admin
// logins, which can't reach the root-only init.sock.
const PowerSocketPath = "/run/sneakers/power.sock"

// Options configure the server.
type Options struct {
	// Allow decides which peer uids may connect; nil means RootOnly
	// (init.sock) or PowerPeerAllowed (power.sock).
	Allow      func(uid uint32) bool
	Supervisor *services.Supervisor
	// Power answers PowerService; nil leaves it Unimplemented.
	Power *power.Controller
	// Callers maps an executable to the caller it is; nil means
	// DefaultCallers.
	Callers map[string]power.Kind
	// ExeOf reads a peer's executable; nil reads /proc/<pid>/exe.
	ExeOf func(pid int32) (string, error)
	// AdminName names the admin a uid belongs to.
	AdminName func(uid uint32) (string, bool)
	// KeyCustody is the custody init unlocked at boot; nil leaves
	// KeyCustodyService Unimplemented.
	KeyCustody *keycustody.Custody
	// SecureBoot is what the firmware reported at boot, for Protection.
	SecureBoot secureboot.State
	Logger     log.Logger
}

// Server is the running API.
type Server struct {
	http *http.Server
}

// Listen creates init.sock (mode 0600, replacing a stale one) and starts
// serving. The services whose bodies later work adds answer Unimplemented.
func Listen(path string, o Options) (*Server, error) {
	if o.Allow == nil {
		o.Allow = RootOnly
	}
	o = o.defaults()
	mux := http.NewServeMux()
	if o.KeyCustody != nil {
		mux.Handle(initv1connect.NewKeyCustodyServiceHandler(&custodyHandler{c: o.KeyCustody, sb: o.SecureBoot, log: o.Logger}))
	} else {
		mux.Handle(initv1connect.NewKeyCustodyServiceHandler(initv1connect.UnimplementedKeyCustodyServiceHandler{}))
	}
	mux.Handle(initv1connect.NewPlatformServiceHandler(initv1connect.UnimplementedPlatformServiceHandler{}))
	mux.Handle(initv1connect.NewImageServiceHandler(initv1connect.UnimplementedImageServiceHandler{}))
	mux.Handle(powerHandlerFor(o))
	mux.Handle(initv1connect.NewServicesServiceHandler(&servicesHandler{s: o.Supervisor, log: o.Logger}))
	return listen(path, 0o600, mux, o)
}

// ListenPower creates power.sock (mode 0666: SO_PEERCRED admits root and
// the admin uids, and PowerService checks the program) serving
// PowerService alone.
func ListenPower(path string, o Options) (*Server, error) {
	if o.Allow == nil {
		o.Allow = PowerPeerAllowed
	}
	o = o.defaults()
	mux := http.NewServeMux()
	mux.Handle(powerHandlerFor(o))
	return listen(path, 0o666, mux, o)
}

// PowerPeerAllowed is power.sock's peer rule: root, or an admin uid (a
// closed-shell login).
func PowerPeerAllowed(uid uint32) bool { return uid == 0 || uid >= access.FirstUID }

func (o Options) defaults() Options {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Callers == nil {
		o.Callers = DefaultCallers
	}
	if o.ExeOf == nil {
		o.ExeOf = procExe
	}
	if o.AdminName == nil {
		o.AdminName = func(uint32) (string, bool) { return "", false }
	}
	return o
}

func listen(path string, mode os.FileMode, mux *http.ServeMux, o Options) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if mode&0o007 != 0 {
		// A socket for other uids is useless in a directory they can't
		// search; the sockets in it keep their own modes.
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil { // #nosec G302 -- searchable only; each socket's mode and SO_PEERCRED decide access
			return nil, err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:           mux,
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       PeerContext,
	}
	logf := func(format string, args ...any) { o.Logger.Warn(fmt.Sprintf(format, args...)) }
	go func() { _ = srv.Serve(PeerListener(ln, o.Allow, logf)) }()
	o.Logger.Info("initapi: listening", log.F("socket", path))
	return &Server{http: srv}, nil
}

// Stop stops serving.
func (s *Server) Stop() { _ = s.http.Close() }

type servicesHandler struct {
	initv1connect.UnimplementedServicesServiceHandler
	s   *services.Supervisor
	log log.Logger
}

func (h *servicesHandler) Start(ctx context.Context, r *connect.Request[initv1.StartRequest]) (*connect.Response[initv1.StartResponse], error) {
	h.log.Info("initapi: Services.Start", log.F("service", r.Msg.GetName()))
	if err := h.s.Start(ctx, r.Msg.GetName()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.StartResponse{}), nil
}

func (h *servicesHandler) Stop(_ context.Context, r *connect.Request[initv1.StopRequest]) (*connect.Response[initv1.StopResponse], error) {
	h.log.Info("initapi: Services.Stop", log.F("service", r.Msg.GetName()))
	if err := h.s.Stop(r.Msg.GetName()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.StopResponse{}), nil
}

func (h *servicesHandler) Status(_ context.Context, r *connect.Request[initv1.StatusRequest]) (*connect.Response[initv1.StatusResponse], error) {
	st, err := h.s.Status(r.Msg.GetName())
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.StatusResponse{Running: st.Running, Ready: st.Ready, Restarts: int32(min(st.Restarts, 1<<30)), LastError: st.LastErr}), nil // #nosec G115 -- clamped
}

// toConnect maps a coded error to a Connect error whose message starts
// with the code's symbol.
func toConnect(err error) error {
	code, ok := codes.Of(err)
	if !ok {
		return connect.NewError(connect.CodeInternal, err)
	}
	c := connect.CodeFailedPrecondition
	switch code {
	case codes.ServiceUnknown:
		c = connect.CodeNotFound
	case codes.ServicePreStart, codes.PowerBusy:
		c = connect.CodeAborted
	case codes.PowerCaller:
		c = connect.CodePermissionDenied
	}
	return connect.NewError(c, errors.New(codes.Describe(err)))
}
