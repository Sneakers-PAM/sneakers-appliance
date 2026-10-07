// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-enrol is the enrol account's forced command during an
// enrolment window (spec 2, Section 2.4): it asks for the code shown on
// the console and offers the key sshd authenticated, which the console's
// typed yes stores. It runs as the enrol uid, which accessd lets reach the
// enrolment calls only.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, enrol.IdleFor)
	defer cancel()
	login, err := accessapi.LoginFromSSH(os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "This login can't be enrolled:", err)
		return 1
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", accessapi.SocketPath)
		},
	}}
	source := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set(accessapi.SourceHeader, login.Source)
			return next(ctx, r)
		}
	})
	c := accessv1connect.NewEnrolmentServiceClient(hc, "http://access.sock", connect.WithInterceptors(source))
	if err := enrol.RunSession(ctx, os.Stdin, os.Stdout, c, login, time.Second); err != nil {
		return 1
	}
	return 0
}
