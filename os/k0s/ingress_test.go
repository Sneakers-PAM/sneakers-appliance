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

type edgeDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		Controller string `yaml:"controller"`
		Template   struct {
			Spec struct {
				ServiceAccountName           string `yaml:"serviceAccountName"`
				AutomountServiceAccountToken *bool  `yaml:"automountServiceAccountToken"`
				Containers                   []struct {
					Name string   `yaml:"name"`
					Args []string `yaml:"args"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
	Rules []struct {
		APIGroups []string `yaml:"apiGroups"`
		Resources []string `yaml:"resources"`
		Verbs     []string `yaml:"verbs"`
	} `yaml:"rules"`
	RoleRef struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		Kind      string `yaml:"kind"`
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"subjects"`
}

func edgeDocs(t *testing.T) []edgeDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "stacks", "edge", "edge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []edgeDoc
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d edgeDoc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, d)
	}
	return docs
}

func traefikFlags(t *testing.T, docs []edgeDoc) (map[string]string, edgeDoc) {
	t.Helper()
	for _, d := range docs {
		if d.Kind != "Deployment" {
			continue
		}
		for _, c := range d.Spec.Template.Spec.Containers {
			if c.Name == "traefik" {
				flags := map[string]string{}
				for _, a := range c.Args {
					k, v, _ := strings.Cut(a, "=")
					flags[k] = v
				}
				return flags, d
			}
		}
	}
	t.Fatal("edge.yaml has no traefik container")
	return nil, edgeDoc{}
}

// The product's charts publish their routes as Ingresses of the class
// traefik, so the edge reads them with the kubernetesingress provider and
// serves them on 443 with the box's certificate as the default.
func TestTheEdgeServesTheProductsIngresses(t *testing.T) {
	docs := edgeDocs(t)
	flags, dep := traefikFlags(t, docs)

	if _, ok := flags["--providers.kubernetesingress"]; !ok {
		t.Fatal("traefik has no kubernetesingress provider")
	}
	if flags["--providers.kubernetesingress.ingressClass"] != "traefik" {
		t.Errorf("the ingress class is %q; want traefik", flags["--providers.kubernetesingress.ingressClass"])
	}
	if _, ok := flags["--providers.file.filename"]; !ok {
		t.Error("the file provider (the /_box/ route) is gone")
	}
	if flags["--entryPoints.websecure.http.tls"] != "true" {
		t.Error("websecure doesn't terminate TLS for every router; an Ingress without a tls block would be served as plain HTTP on 443")
	}

	var class bool
	for _, d := range docs {
		if d.Kind == "IngressClass" && d.Metadata.Name == "traefik" {
			class = d.Spec.Controller == "traefik.io/ingress-controller" // scrub:allow=fqdn
		}
	}
	if !class {
		t.Error("no IngressClass traefik for the Traefik controller")
	}

	sa := dep.Spec.Template.Spec.ServiceAccountName
	if sa == "" || dep.Spec.Template.Spec.AutomountServiceAccountToken == nil || !*dep.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatalf("traefik runs without its own service account token (serviceAccountName %q)", sa)
	}
	bound := map[string]edgeDoc{}
	for _, d := range docs {
		if d.Kind != "ClusterRoleBinding" && d.Kind != "RoleBinding" {
			continue
		}
		for _, s := range d.Subjects {
			if s.Kind == "ServiceAccount" && s.Name == sa && s.Namespace == "sneakers-edge" {
				bound[d.RoleRef.Kind+"/"+d.RoleRef.Name] = d
			}
		}
	}
	can := func(resource, verb string) bool {
		for _, d := range docs {
			if _, ok := bound[d.Kind+"/"+d.Metadata.Name]; !ok {
				continue
			}
			for _, r := range d.Rules {
				if slices.Contains(r.Resources, resource) && slices.Contains(r.Verbs, verb) {
					return true
				}
			}
		}
		return false
	}
	for _, res := range []string{"ingresses", "ingressclasses", "services", "endpointslices", "secrets", "nodes"} {
		for _, verb := range []string{"get", "list", "watch"} {
			if !can(res, verb) {
				t.Errorf("traefik's service account can't %s %s", verb, res)
			}
		}
	}
}

// With Ingresses in play the lab hello route must not shadow them: it keeps
// the lowest priority, so a product Ingress for / wins whenever one exists.
func TestTheHelloRouteYieldsToTheProductsIngresses(t *testing.T) {
	cfg := edgeConfig(t)
	r, ok := cfg.HTTP.Routers["hello"]
	if !ok {
		t.Fatal("no hello router")
	}
	if r.Priority != 1 {
		t.Errorf("the hello router's priority is %d; want 1", r.Priority)
	}
}
