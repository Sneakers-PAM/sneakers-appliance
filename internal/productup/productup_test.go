// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeK0s answers the k0s commands from what the test sets.
type fakeK0s struct {
	apiUp    bool
	images   string
	stacks   map[string]bool
	podsJSON string
	// workloads is the stacks' Deployments, StatefulSets and DaemonSets as
	// JSON; empty is none.
	workloads string
	calls     []string
}

func (f *fakeK0s) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	f.calls = append(f.calls, filepath.Base(name)+" "+line)
	switch {
	case strings.Contains(line, "/readyz"):
		if !f.apiUp {
			return nil, errors.New("connection refused")
		}
		return []byte("ok"), nil
	case strings.HasPrefix(line, "ctr "):
		return []byte(f.images), nil
	case strings.Contains(line, productup.StackLabel+"="):
		for s, ok := range f.stacks {
			if ok && strings.Contains(line, productup.StackLabel+"="+s+" ") {
				return []byte("namespace/" + s + "\n"), nil
			}
		}
		return nil, nil
	case strings.Contains(line, "get pods"):
		return []byte(f.podsJSON), nil
	case strings.Contains(line, "get deployments,statefulsets,daemonsets"):
		if f.workloads == "" {
			return []byte(`{"items":[]}`), nil
		}
		return []byte(f.workloads), nil
	}
	return nil, errors.New("unexpected " + line)
}

func slot(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, p := range []string{"images/" + hexA + ".tar", "images/" + hexB + ".tar", "manifests/edge/edge.yaml", "manifests/hello/hello.yaml"} {
		if err := os.MkdirAll(filepath.Join(d, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, p), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func edge(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return s
}

func probe(t *testing.T, k *fakeK0s, e *httptest.Server) *productup.Probe {
	t.Helper()
	return &productup.Probe{Slot: slot(t), DataDir: "/var/lib/k0s", Containerd: "/run/k0s/containerd.sock", Edge: strings.TrimPrefix(e.URL, "https://"), Run: k.run, HTTP: e.Client()}
}

func check(t *testing.T, p *productup.Probe) productup.Result {
	t.Helper()
	r, err := p.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const twoPods = `{"items":[
 {"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},
 {"status":{"phase":"Running","conditions":[{"type":"Ready","status":"%s"}]}},
 {"status":{"phase":"Succeeded","conditions":[{"type":"Ready","status":"False"}]}}]}`

// The product comes up step by step: the API, the images, the stacks,
// the pods, and the edge answering with the product rather than
// edgefall's page or an edge error.
func TestTheProbeFollowsEachStep(t *testing.T) {
	boxPage := true
	e := edge(t, func(w http.ResponseWriter, _ *http.Request) {
		if boxPage {
			w.Header().Set(productup.StateHeader, "starting")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	k := &fakeK0s{stacks: map[string]bool{}}
	p := probe(t, k, e)
	if r := check(t, p); r.Step != productup.StepK0s {
		t.Fatalf("API down: %+v", r)
	}
	k.apiUp = true
	k.images = "REF TYPE DIGEST\nexample/a:1 application/vnd.oci.image.index.v1+json sha256:" + hexA + "\n"
	if r := check(t, p); r.Step != productup.StepImages || r.Detail != "1 of 2 images imported" {
		t.Fatalf("one image: %+v", r)
	}
	k.images += "example/b:1 application/vnd.oci.image.index.v1+json sha256:" + hexB + "\n"
	k.stacks["edge"] = true
	if r := check(t, p); r.Step != productup.StepManifests || r.Detail != "Waiting for hello" {
		t.Fatalf("one stack: %+v", r)
	}
	k.stacks["hello"] = true
	k.podsJSON = strings.Replace(twoPods, "%s", "False", 1)
	if r := check(t, p); r.Step != productup.StepPods || r.Detail != "1 of 2 pods ready" {
		t.Fatalf("one pod: %+v", r)
	}
	k.podsJSON = strings.Replace(twoPods, "%s", "True", 1)
	if r := check(t, p); r.Step != productup.StepEdge {
		t.Fatalf("pods ready, the edge still the box page: %+v", r)
	}
	boxPage = false
	if r := check(t, p); r.Step != "" {
		t.Fatalf("up: %+v", r)
	}
}

// An edge error (502 to 504, the product behind it not ready) isn't the
// product; a 404 for a path with no route is the edge answering.
func TestAnEdgeErrorIsNotUp(t *testing.T) {
	status := http.StatusBadGateway
	e := edge(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	k := &fakeK0s{apiUp: true, images: "sha256:" + hexA + " sha256:" + hexB, stacks: map[string]bool{"edge": true, "hello": true}, podsJSON: strings.Replace(twoPods, "%s", "True", 1)}
	p := probe(t, k, e)
	if r := check(t, p); r.Step != productup.StepEdge {
		t.Fatalf("502: %+v", r)
	}
	status = http.StatusNotFound
	if r := check(t, p); r.Step != "" {
		t.Fatalf("404: %+v", r)
	}
}

// A stack whose switch is off isn't applied, so it isn't waited for.
func TestASwitchedOffStackIsntWaitedFor(t *testing.T) {
	e := edge(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	k := &fakeK0s{apiUp: true, images: "sha256:" + hexA + " sha256:" + hexB, stacks: map[string]bool{"edge": true}, podsJSON: strings.Replace(twoPods, "%s", "True", 1)}
	p := probe(t, k, e)
	if r := check(t, p); r.Step != productup.StepManifests {
		t.Fatalf("hello is waited for: %+v", r)
	}
	if err := os.WriteFile(filepath.Join(p.Slot, "switch-stacks"), []byte("hi hello off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.SwitchDir = t.TempDir()
	if r := check(t, p); r.Step != "" {
		t.Fatalf("a switched-off stack is waited for: %+v", r)
	}
}

// k0s is asked with the bundle's own binary and the admin kubeconfig in
// its data directory.
func TestTheProbeUsesTheBundlesK0s(t *testing.T) {
	e := edge(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	k := &fakeK0s{}
	p := probe(t, k, e)
	check(t, p)
	if len(k.calls) != 1 || k.calls[0] != "k0s kubectl --kubeconfig /var/lib/k0s/pki/admin.conf get --raw /readyz" {
		t.Fatalf("calls %q", k.calls)
	}
}

const rollingOut = `{"items":[{"kind":"Deployment","metadata":{"namespace":"sneakers","name":"sneakers-gateway","generation":3,"labels":{"k0s.k0sproject.io/stack":"sneakers"}},
 "spec":{"replicas":1},"status":{"observedGeneration":3,"replicas":2,"updatedReplicas":%d,"availableReplicas":1,"readyReplicas":1}}]}`

const oldPodStopping = `{"items":[
 {"metadata":{"name":"gw-new"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"gw-old","deletionTimestamp":"2026-10-09T18:00:00Z"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}]}`

// An update over a running product isn't done while the edge answers from
// the old pods: each stack's workloads must have rolled out (every replica
// updated and available, the latest generation seen) and the old pods must
// be gone first.
func TestAnUpdateWaitsForTheRolloutAndTheOldPods(t *testing.T) {
	e := edge(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	k := &fakeK0s{apiUp: true, images: "sha256:" + hexA + " sha256:" + hexB, stacks: map[string]bool{"edge": true, "hello": true},
		podsJSON: strings.Replace(twoPods, "%s", "True", 1), workloads: strings.Replace(rollingOut, "%d", "0", 1)}
	p := probe(t, k, e)
	if r := check(t, p); r.Step != productup.StepPods || !strings.Contains(r.Detail, "sneakers/sneakers-gateway") {
		t.Fatalf("the old pods still answer, the rollout hasn't started: %+v", r)
	}
	k.workloads = strings.Replace(strings.Replace(rollingOut, "%d", "1", 1), `"replicas":2`, `"replicas":1`, 1)
	k.podsJSON = oldPodStopping
	if r := check(t, p); r.Step != productup.StepPods || r.Detail != "1 old pod still stopping" {
		t.Fatalf("rolled out, an old pod stopping: %+v", r)
	}
	k.podsJSON = strings.Replace(twoPods, "%s", "True", 1)
	if r := check(t, p); r.Step != "" {
		t.Fatalf("rolled out and the old pods gone: %+v", r)
	}
}
