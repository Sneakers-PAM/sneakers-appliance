// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type edgeDynamic struct {
	HTTP struct {
		Routers map[string]struct {
			Rule        string    `yaml:"rule"`
			EntryPoints []string  `yaml:"entryPoints"`
			Service     string    `yaml:"service"`
			Priority    int       `yaml:"priority"`
			Middlewares []string  `yaml:"middlewares"`
			TLS         *struct{} `yaml:"tls"`
		} `yaml:"routers"`
		Middlewares map[string]struct {
			Errors *struct {
				Status  []string `yaml:"status"`
				Service string   `yaml:"service"`
				Query   string   `yaml:"query"`
			} `yaml:"errors"`
		} `yaml:"middlewares"`
		Services map[string]struct {
			LoadBalancer struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
			} `yaml:"loadBalancer"`
		} `yaml:"services"`
	} `yaml:"http"`
}

func edgeConfig(t *testing.T) edgeDynamic {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "edge", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d.Kind != "ConfigMap" || d.Data["dynamic.yaml"] == "" {
			continue
		}
		var cfg edgeDynamic
		if err := yaml.Unmarshal([]byte(d.Data["dynamic.yaml"]), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	t.Fatal("edge.yaml has no dynamic.yaml")
	return edgeDynamic{}
}

// The edge sends /_box/ to sneakers-edgefall on loopback (docs/edge-fallback.md),
// ahead of the product's catch-all route, so a product page gets the box
// state from its own origin.
func TestTheEdgeRoutesTheBoxStateToEdgefall(t *testing.T) {
	cfg := edgeConfig(t)
	var box string
	for name, r := range cfg.HTTP.Routers {
		if r.Rule == "PathPrefix(`/_box/`)" {
			box = name
		}
	}
	if box == "" {
		t.Fatal("no router for /_box/")
	}
	r := cfg.HTTP.Routers[box]
	if !slices.Equal(r.EntryPoints, []string{"websecure"}) || r.TLS == nil || r.Priority <= cfg.HTTP.Routers["hello"].Priority || r.Priority < 1000 {
		t.Fatalf("the /_box/ router: %+v", r)
	}
	if len(r.Middlewares) != 0 {
		t.Fatalf("the /_box/ router has middlewares %v", r.Middlewares)
	}
	srv := cfg.HTTP.Services[r.Service].LoadBalancer.Servers
	if len(srv) != 1 || srv[0].URL != "http://127.0.0.1:9180" {
		t.Fatalf("the /_box/ service: %+v", srv)
	}
}

// When the product behind a route doesn't answer (502 to 504), the edge
// serves edgefall's box-state page instead of its own error.
func TestTheProductRoutesFallBackToTheBoxStatePage(t *testing.T) {
	cfg := edgeConfig(t)
	box := ""
	for _, r := range cfg.HTTP.Routers {
		if r.Rule == "PathPrefix(`/_box/`)" {
			box = r.Service
		}
	}
	for name, r := range cfg.HTTP.Routers {
		if r.Service == box {
			continue
		}
		found := false
		for _, m := range r.Middlewares {
			e := cfg.HTTP.Middlewares[m].Errors
			if e != nil && slices.Equal(e.Status, []string{"502-504"}) && e.Service == box && strings.HasPrefix(e.Query, "/_box/") {
				found = true
			}
		}
		if !found {
			t.Errorf("router %s doesn't fall back to the box-state page", name)
		}
	}
}

// The lab hello page loads the poller, so an open tab shows the box-state
// page through a reboot and comes back by itself.
func TestTheHelloPageLoadsThePoller(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "hello", "hello.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`<script src="/_box/poll.js" defer></script>`)) || !bytes.Contains(b, []byte("hello from sneakers-appliance")) {
		t.Fatal("the hello page doesn't load /_box/poll.js")
	}
}
