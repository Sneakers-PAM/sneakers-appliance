// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootrotate"
)

// rootKeyHeader is the response header the vault's health check carries its
// root key move status in: {"state":"none|in-progress|verified|failed","pending":n}.
// It holds a state and a count, never a key.
const rootKeyHeader = "Sneakers-Root-Key"

// RootKeyStatus asks the pod of the workload ns/kind/name that started at or
// after notBefore what it says about the move of its root key. The pod's own
// address is asked (the node reaches it): the health port named HEALTH_PORT
// in its container's environment, which the vault serves without TLS, or the
// container's first port when it isn't set. An error means there is no such
// pod yet, or it doesn't answer; the caller asks again.
func (p *Probe) RootKeyStatus(ctx context.Context, ns, kind, name string, notBefore time.Time) (rootrotate.VaultStatus, error) {
	out, err := p.kubectl(ctx, "get", strings.ToLower(kind), name, "--namespace", ns, "-o", "json")
	if err != nil {
		return rootrotate.VaultStatus{}, err
	}
	var w struct {
		Spec struct {
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
			Template struct {
				Spec struct {
					Containers []struct {
						Ports []struct {
							ContainerPort int `json:"containerPort"`
						} `json:"ports"`
						Env []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"env"`
						EnvFrom []struct {
							ConfigMapRef *struct {
								Name string `json:"name"`
							} `json:"configMapRef"`
						} `json:"envFrom"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(out, &w); err != nil {
		return rootrotate.VaultStatus{}, fmt.Errorf("the workload doesn't parse: %w", err)
	}
	if len(w.Spec.Selector.MatchLabels) == 0 || len(w.Spec.Template.Spec.Containers) == 0 {
		return rootrotate.VaultStatus{}, errors.New("the workload has no selector or container")
	}
	port := ""
	for _, c := range w.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "HEALTH_PORT" && e.Value != "" {
				port = e.Value
			}
		}
		// The chart puts HEALTH_PORT in the service's ConfigMap.
		for _, ef := range c.EnvFrom {
			if port != "" || ef.ConfigMapRef == nil {
				continue
			}
			cm, err := p.kubectl(ctx, "get", "configmap", ef.ConfigMapRef.Name, "--namespace", ns, "-o", "json")
			if err != nil {
				continue
			}
			var d struct {
				Data map[string]string `json:"data"`
			}
			if json.Unmarshal(cm, &d) == nil {
				port = d.Data["HEALTH_PORT"]
			}
		}
		if port == "" && len(c.Ports) > 0 {
			port = fmt.Sprint(c.Ports[0].ContainerPort)
		}
		if port != "" {
			break
		}
	}
	if port == "" {
		return rootrotate.VaultStatus{}, errors.New("the workload names no health port")
	}
	sel := make([]string, 0, len(w.Spec.Selector.MatchLabels))
	for k, v := range w.Spec.Selector.MatchLabels {
		sel = append(sel, k+"="+v)
	}
	sort.Strings(sel)
	out, err = p.kubectl(ctx, "get", "pods", "--namespace", ns, "-l", strings.Join(sel, ","), "-o", "json")
	if err != nil {
		return rootrotate.VaultStatus{}, err
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				DeletionTimestamp *string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Status struct {
				PodIP     string    `json:"podIP"`
				StartTime time.Time `json:"startTime"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &pods); err != nil {
		return rootrotate.VaultStatus{}, fmt.Errorf("the pod list doesn't parse: %w", err)
	}
	ip, newest := "", time.Time{}
	for _, it := range pods.Items {
		if it.Metadata.DeletionTimestamp != nil || it.Status.PodIP == "" || it.Status.StartTime.Before(notBefore) {
			continue
		}
		if it.Status.StartTime.After(newest) || ip == "" {
			ip, newest = it.Status.PodIP, it.Status.StartTime
		}
	}
	if ip == "" {
		return rootrotate.VaultStatus{}, errors.New("no pod of the workload has started since the restart")
	}
	return p.askRootKey(ctx, net.JoinHostPort(ip, port))
}

func (p *Probe) askRootKey(ctx context.Context, addr string) (rootrotate.VaultStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, p.askTimeout())
	defer cancel()
	// The vault's health check is gRPC (grpc.health.v1.Health/Check, no
	// service), on a port without TLS: HTTP/2 in the clear, one empty message
	// in gRPC's five-byte frame. The status is in the response's headers.
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: &protos}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/grpc.health.v1.Health/Check", bytes.NewReader(make([]byte, 5)))
	if err != nil {
		return rootrotate.VaultStatus{}, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := (&http.Client{Transport: tr, Timeout: p.askTimeout()}).Do(req)
	if err != nil {
		return rootrotate.VaultStatus{}, fmt.Errorf("the vault's health port doesn't answer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	h := resp.Header.Get(rootKeyHeader)
	if h == "" {
		return rootrotate.VaultStatus{}, fmt.Errorf("the vault's health check (HTTP %d) carries no root key status", resp.StatusCode)
	}
	var s struct {
		State   string `json:"state"`
		Pending int    `json:"pending"`
	}
	if err := json.Unmarshal([]byte(h), &s); err != nil {
		return rootrotate.VaultStatus{}, fmt.Errorf("the root key status doesn't parse: %w", err)
	}
	switch s.State {
	case rootrotate.StateNone, rootrotate.StateInProgress, rootrotate.StateVerified, rootrotate.StateFailed:
		return rootrotate.VaultStatus{State: s.State, Pending: s.Pending}, nil
	}
	return rootrotate.VaultStatus{}, fmt.Errorf("the root key status names an unknown state %q", s.State)
}
