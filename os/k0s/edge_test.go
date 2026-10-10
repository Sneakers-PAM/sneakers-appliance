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
					Command        []string `yaml:"command"`
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
// Traefik comes up. Traefik's own container asks on edgefall's loopback
// listener (its busybox wget) right before it execs traefik, so 443 is
// free only for the moment Traefik takes to bind it, not for the kubelet
// starting another container on a box that starts every pod at once; and
// a failure (no edgefall) never stops Traefik.
func TestTheEdgeAsksEdgefallForThePortsRightBeforeTraefikBinds(t *testing.T) {
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
		if len(s.InitContainers) != 0 || len(s.Containers) != 1 {
			t.Fatalf("init containers %+v", s.InitContainers)
		}
		c := s.Containers[0]
		if len(c.Command) != 4 || c.Command[0] != "/bin/sh" || c.Command[1] != "-c" || c.Command[3] != "traefik" {
			t.Fatalf("traefik's command %q", c.Command)
		}
		script := c.Command[2]
		handoff, run, ok := strings.Cut(script, ";")
		if !ok || !strings.Contains(handoff, "wget") || !strings.Contains(handoff, "--post-data=") ||
			!strings.Contains(handoff, "http://127.0.0.1:9180/_box/edge-handoff") || !strings.HasSuffix(strings.TrimSpace(handoff), "|| true") ||
			strings.TrimSpace(run) != `exec traefik "$@"` {
			t.Fatalf("traefik's start %q", script)
		}
		if len(c.Args) == 0 || !strings.HasPrefix(c.Args[0], "--entryPoints.") {
			t.Fatalf("traefik's args %q", c.Args)
		}
		return
	}
	t.Fatal("edge.yaml has no Deployment")
}

// The edge's file provider reads the routes and the default certificate
// from one projected directory: the edge ConfigMap, and the box-tls
// Secret's Traefik config as tls.yaml (optional, so the edge starts without
// it). The kubelet updates the directory when the Secret changes and
// Traefik reloads it, so a new certificate needs no restart.
func TestTheEdgeReadsItsCertificateFromAWatchedDirectory(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "edge", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d struct {
			Kind string `yaml:"kind"`
			Data map[string]string
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							VolumeMounts []struct {
								Name      string `yaml:"name"`
								MountPath string `yaml:"mountPath"`
							} `yaml:"volumeMounts"`
						} `yaml:"containers"`
						Volumes []struct {
							Name      string `yaml:"name"`
							Projected *struct {
								Sources []struct {
									ConfigMap *struct{ Name string } `yaml:"configMap"`
									Secret    *struct {
										Name     string `yaml:"name"`
										Optional bool   `yaml:"optional"`
										Items    []struct{ Key, Path string }
									} `yaml:"secret"`
								} `yaml:"sources"`
							} `yaml:"projected"`
						} `yaml:"volumes"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d.Kind == "ConfigMap" && strings.Contains(d.Data["dynamic.yaml"], "certFile") {
			t.Fatal("the routes' ConfigMap still names a certificate file")
		}
		if d.Kind != "Deployment" {
			continue
		}
		s := d.Spec.Template.Spec
		if len(s.Volumes) != 1 || s.Volumes[0].Projected == nil || len(s.Containers[0].VolumeMounts) != 1 || s.Containers[0].VolumeMounts[0].MountPath != "/etc/traefik/dynamic" {
			t.Fatalf("volumes %+v mounts %+v", s.Volumes, s.Containers[0].VolumeMounts)
		}
		src := s.Volumes[0].Projected.Sources
		if len(src) != 2 || src[0].ConfigMap == nil || src[0].ConfigMap.Name != "edge" || src[1].Secret == nil || src[1].Secret.Name != "box-tls" || !src[1].Secret.Optional ||
			len(src[1].Secret.Items) != 1 || src[1].Secret.Items[0].Key != "traefik-tls.yaml" || src[1].Secret.Items[0].Path != "tls.yaml" {
			t.Fatalf("sources %+v", src)
		}
		return
	}
	t.Fatal("edge.yaml has no Deployment")
}

// Every request on 443 passes edgefall's gate first (a forwardAuth
// middleware on the websecure entry point), so while the box is starting
// or updating the product's own routes, sign-in and MCP included, answer
// the box-state page instead of a product that isn't ready.
func TestTheEdgeGatesEveryRequestOn443OnEdgefall(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "edge", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var gated bool
	var dynamic string
	for {
		var d struct {
			Data           map[string]string `yaml:"data"`
			edgeDeployment `yaml:",inline"`
		}
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d.Kind == "ConfigMap" {
			dynamic = d.Data["dynamic.yaml"]
		}
		if d.Kind != "Deployment" {
			continue
		}
		for _, c := range d.Spec.Template.Spec.Containers {
			for _, a := range c.Args {
				if a == "--entryPoints.websecure.http.middlewares=box-gate@file" {
					gated = true
				}
			}
		}
	}
	if !gated {
		t.Fatal("the websecure entry point doesn't use the box-gate middleware")
	}
	var cfg struct {
		HTTP struct {
			Middlewares map[string]struct {
				ForwardAuth *struct {
					Address string `yaml:"address"`
				} `yaml:"forwardAuth"`
			} `yaml:"middlewares"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal([]byte(dynamic), &cfg); err != nil {
		t.Fatal(err)
	}
	fa := cfg.HTTP.Middlewares["box-gate"].ForwardAuth
	if fa == nil || fa.Address != "http://127.0.0.1:9180/_box/gate" {
		t.Fatalf("box-gate is %+v; want a forwardAuth to edgefall's /_box/gate", fa)
	}
}
