// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type edgeDeployment struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Template struct {
			Spec struct {
				InitContainers []struct {
					Name    string   `yaml:"name"`
					Image   string   `yaml:"image"`
					Command []string `yaml:"command"`
				} `yaml:"initContainers"`
				Containers []struct {
					Name           string   `yaml:"name"`
					Image          string   `yaml:"image"`
					Args           []string `yaml:"args"`
					ReadinessProbe *struct {
						HTTPGet *struct {
							Host   string `yaml:"host"`
							Path   string `yaml:"path"`
							Port   int    `yaml:"port"`
							Scheme string `yaml:"scheme"`
						} `yaml:"httpGet"`
					} `yaml:"readinessProbe"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// Traefik serves ping as its own router with no TLS, so on an entry point
// that isn't TLS by itself an HTTPS probe reaches the product routes
// instead (the hello route's PathPrefix(/) answered 404). Spec 3 gives ping
// its own entry point on loopback, which the probe reaches over plain HTTP
// and clients never see.
func TestTheEdgeProbesTraefiksPingOnItsOwnLoopbackEntryPoint(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "edge", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var found bool
	for {
		var d edgeDeployment
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d.Kind != "Deployment" {
			continue
		}
		for _, c := range d.Spec.Template.Spec.Containers {
			if c.Name != "traefik" {
				continue
			}
			found = true
			flags := map[string]string{}
			for _, a := range c.Args {
				k, v, _ := strings.Cut(a, "=")
				flags[k] = v
			}
			ep := flags["--ping.entryPoint"]
			if ep == "" || ep == "web" || ep == "websecure" {
				t.Fatalf("ping is on the entry point %q; want its own", ep)
			}
			host, port, err := net.SplitHostPort(flags["--entryPoints."+ep+".address"])
			if err != nil || host != "127.0.0.1" {
				t.Fatalf("the ping entry point %s listens on %q; want 127.0.0.1:<port>", ep, flags["--entryPoints."+ep+".address"])
			}
			if _, tls := flags["--entryPoints."+ep+".http.tls"]; tls {
				t.Errorf("the ping entry point %s has TLS; the probe speaks plain HTTP", ep)
			}
			p := c.ReadinessProbe
			if p == nil || p.HTTPGet == nil {
				t.Fatal("the edge has no HTTP readiness probe")
			}
			g := p.HTTPGet
			if g.Host != host || strconv.Itoa(g.Port) != port || g.Path != "/ping" || (g.Scheme != "" && g.Scheme != "HTTP") {
				t.Errorf("the readiness probe gets %s://%s:%d%s; want http://%s:%s/ping", g.Scheme, g.Host, g.Port, g.Path, host, port)
			}
		}
	}
	if !found {
		t.Fatal("edge.yaml has no traefik container")
	}
}

// edgefall holds 443 from k0s's start until the edge asks for it, so the
// product URL answers with the box-state page instead of refusing while
// Traefik comes up. The edge's init container asks on edgefall's loopback
// listener, just before Traefik binds, from Traefik's own image (its
// busybox wget), and never fails the pod when edgefall doesn't answer.
func TestTheEdgeAsksEdgefallForThePortsBeforeTraefikStarts(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "edge", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d edgeDeployment
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d.Kind != "Deployment" {
			continue
		}
		s := d.Spec.Template.Spec
		if len(s.InitContainers) != 1 || len(s.Containers) == 0 {
			t.Fatalf("init containers %+v", s.InitContainers)
		}
		ic := s.InitContainers[0]
		cmd := strings.Join(ic.Command, " ")
		if ic.Image != s.Containers[0].Image || !strings.Contains(cmd, "wget") || !strings.Contains(cmd, "--post-data=") ||
			!strings.Contains(cmd, "http://127.0.0.1:9180/_box/edge-handoff") || !strings.HasSuffix(strings.TrimSpace(cmd), "|| true") {
			t.Fatalf("the handoff init container is %s %q", ic.Image, cmd)
		}
		return
	}
	t.Fatal("edge.yaml has no Deployment")
}
