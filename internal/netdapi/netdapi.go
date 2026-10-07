// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package netdapi is what netd's callers share with it: the socket and a
// Connect client over it. Only root peers may connect.
package netdapi

import (
	"context"
	"net"
	"net/http"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
)

// SocketPath is where netd listens.
const SocketPath = "/run/sneakers/netd.sock"

// NewClient returns a NetworkService client over the unix socket sock.
// It sets no overall timeout, since Watch is a long-lived stream; callers
// bound each call with their context.
func NewClient(sock string) netdv1connect.NetworkServiceClient {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	return netdv1connect.NewNetworkServiceClient(hc, "http://netd.sock")
}
