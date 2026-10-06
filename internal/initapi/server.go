// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package initapi serves init's local API on /run/sneakers/init.sock
// (proto sneakers.appliance.init.v1) with Connect, which also speaks the
// gRPC protocol. Only root may connect; every connection's peer is checked
// with SO_PEERCRED before a request is read.
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// SocketPath is where the API listens.
const SocketPath = "/run/sneakers/init.sock"

// Options configure the server.
type Options struct {
	// Allow decides which peer uids may connect; nil means RootOnly.
	Allow      func(uid uint32) bool
	Supervisor *services.Supervisor
	Logger     log.Logger
}

// Server is the running API.
type Server struct {
	http *http.Server
}

// Listen creates the socket (mode 0600, replacing a stale one) and starts
// serving. The services whose bodies later work adds answer Unimplemented.
func Listen(path string, o Options) (*Server, error) {
	if o.Allow == nil {
		o.Allow = RootOnly
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(initv1connect.NewKeyCustodyServiceHandler(initv1connect.UnimplementedKeyCustodyServiceHandler{}))
	mux.Handle(initv1connect.NewPlatformServiceHandler(initv1connect.UnimplementedPlatformServiceHandler{}))
	mux.Handle(initv1connect.NewImageServiceHandler(initv1connect.UnimplementedImageServiceHandler{}))
	mux.Handle(initv1connect.NewPowerServiceHandler(initv1connect.UnimplementedPowerServiceHandler{}))
	mux.Handle(initv1connect.NewServicesServiceHandler(&servicesHandler{s: o.Supervisor, log: o.Logger}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:           mux,
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(peerConn); ok {
				return context.WithValue(ctx, peerKey{}, pc.peer)
			}
			return ctx
		},
	}
	logf := func(format string, args ...any) { o.Logger.Warn(fmt.Sprintf(format, args...)) }
	go func() { _ = srv.Serve(peerListener{Listener: ln, allow: o.Allow, logf: logf}) }()
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
	case codes.ServicePreStart:
		c = connect.CodeAborted
	}
	return connect.NewError(c, errors.New(codes.Describe(err)))
}
