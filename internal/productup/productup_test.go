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
	"slices"
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
	// health is the product's health check's answer: nil is ready.
	health error
	calls  []string
}

func (f *fakeK0s) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	f.calls = append(f.calls, filepath.Base(name)+" "+line)
	switch {
	case strings.Contains(line, "/proxy/"):
		if f.health != nil {
			return nil, f.health
		}
		return []byte("ok"), nil
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

func writeSlot(t *testing.T, slot string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		if err := os.MkdirAll(filepath.Join(slot, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(slot, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The slot's hello stack: a Deployment at the new version, next to a
// ConfigMap that isn't a workload.
const helloStack = `apiVersion: v1
kind: ConfigMap
metadata:
  name: hello
  namespace: hello
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: hello
spec:
  template:
    spec:
      initContainers:
        - name: wait
          image: example.org/wait@sha256:1111
      containers:
        - name: web
          image: example.org/web@sha256:2222
`

// liveWeb is hello/web as the cluster has it, rolled out, with web's
// image.
const liveWeb = `{"items":[{"kind":"Deployment","metadata":{"namespace":"hello","name":"web","generation":4,"labels":{"k0s.k0sproject.io/stack":"hello"}},
 "spec":{"replicas":1,"template":{"spec":{"initContainers":[{"name":"wait","image":"example.org/wait@sha256:1111"}],"containers":[{"name":"web","image":"%s"}]}}},
 "status":{"observedGeneration":4,"replicas":1,"updatedReplicas":1,"availableReplicas":1,"readyReplicas":1}}]}`

func readyProbe(t *testing.T, k *fakeK0s) *productup.Probe {
	t.Helper()
	e := edge(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	k.apiUp, k.images = true, "sha256:"+hexA+" sha256:"+hexB
	k.stacks = map[string]bool{"edge": true, "hello": true}
	k.podsJSON = strings.Replace(twoPods, "%s", "True", 1)
	p := probe(t, k, e)
	writeSlot(t, p.Slot, map[string]string{"manifests/hello/hello.yaml": helloStack})
	return p
}

// Right after the restart k0s hasn't applied the new slot's stacks yet:
// the old workloads have rolled out at their own generation and the old
// pods answer. The workloads must run the slot's version before they
// count, so the update isn't done until k0s has applied it and it has
// rolled out.
func TestAnUpdateWaitsUntilTheWorkloadsRunTheSlotsVersion(t *testing.T) {
	k := &fakeK0s{workloads: strings.Replace(liveWeb, "%s", "example.org/web@sha256:0000", 1)}
	p := readyProbe(t, k)
	r := check(t, p)
	if r.Step != productup.StepPods || !strings.HasPrefix(r.Detail, "Rolling out (0 of 1 ready)") || !strings.Contains(r.Detail, "hello/web") {
		t.Fatalf("the old version still runs: %+v", r)
	}
	k.workloads = strings.Replace(liveWeb, "%s", "example.org/web@sha256:2222", 1)
	if r := check(t, p); r.Step != "" {
		t.Fatalf("the slot's version rolled out: %+v", r)
	}
}

// A workload the slot adds isn't there until k0s creates it.
func TestANewWorkloadIsWaitedFor(t *testing.T) {
	k := &fakeK0s{}
	p := readyProbe(t, k)
	if r := check(t, p); r.Step != productup.StepPods || r.Detail != "Rolling out (0 of 1 ready): waiting for hello/web, not created yet" {
		t.Fatalf("hello/web isn't there: %+v", r)
	}
}

// The count covers every workload: the slot's and those k0s labels.
func TestTheRolloutCountsEachWorkload(t *testing.T) {
	k := &fakeK0s{}
	p := readyProbe(t, k)
	k.workloads = `{"items":[` + strings.TrimSuffix(strings.TrimPrefix(strings.Replace(liveWeb, "%s", "example.org/web@sha256:2222", 1), `{"items":[`), `]}`) + `,
 {"kind":"StatefulSet","metadata":{"namespace":"hello","name":"db","generation":2},"spec":{"replicas":1},
  "status":{"observedGeneration":2,"replicas":1,"updatedReplicas":1,"availableReplicas":0,"readyReplicas":0,"currentRevision":"db-1","updateRevision":"db-2"}}]}`
	if r := check(t, p); r.Step != productup.StepPods || !strings.HasPrefix(r.Detail, "Rolling out (1 of 2 ready): waiting for hello/db") {
		t.Fatalf("db still rolling: %+v", r)
	}
}

const crashingPod = `{"items":[
 {"metadata":{"namespace":"hello","name":"web-new"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}],
  "containerStatuses":[{"name":"web","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},
 {"metadata":{"namespace":"hello","name":"web-evicted"},"status":{"phase":"Failed","reason":"Evicted"}},
 {"metadata":{"namespace":"hello","name":"db-0"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}]}`

// A pod that keeps failing holds the rollout, and the step says which pod
// and why; a pod that has failed for good (evicted, say) is gone and isn't
// waited for.
func TestAFailingPodIsNamed(t *testing.T) {
	k := &fakeK0s{workloads: strings.Replace(liveWeb, "%s", "example.org/web@sha256:2222", 1)}
	p := readyProbe(t, k)
	k.podsJSON = crashingPod
	if r := check(t, p); r.Step != productup.StepPods || r.Detail != "1 of 2 pods ready: hello/web-new CrashLoopBackOff" {
		t.Fatalf("a crash-looping pod: %+v", r)
	}
}

const readyYAML = `format: 2
ready:
  health:
    service: hello/web:http
    path: /readyz
  timeout: 4m
`

// With the workloads rolled out, the product's own health check, as its
// product.yaml declares it, must answer before the edge counts.
func TestTheProductsHealthCheckMustAnswer(t *testing.T) {
	k := &fakeK0s{workloads: strings.Replace(liveWeb, "%s", "example.org/web@sha256:2222", 1)}
	p := readyProbe(t, k)
	writeSlot(t, p.Slot, map[string]string{"product.yaml": readyYAML})
	k.health = errors.New("the server is currently unable to handle the request")
	if r := check(t, p); r.Step != productup.StepHealth || r.Detail != "hello/web:http /readyz doesn't answer ready yet" {
		t.Fatalf("not healthy: %+v", r)
	}
	if !slices.Contains(k.calls, "k0s kubectl --kubeconfig /var/lib/k0s/pki/admin.conf get --raw /api/v1/namespaces/hello/services/web:http/proxy/readyz") {
		t.Fatalf("calls %q", k.calls)
	}
	k.health = nil
	if r := check(t, p); r.Step != "" {
		t.Fatalf("healthy: %+v", r)
	}
}

// A stack that holds no workload (only a ServiceAccount, say) still counts
// as applied once k0s has put its objects in.
func TestAStackOfOtherKindsCountsAsApplied(t *testing.T) {
	k := &fakeK0s{}
	p := readyProbe(t, k)
	k.workloads = strings.Replace(liveWeb, "%s", "example.org/web@sha256:2222", 1)
	check(t, p)
	for _, c := range k.calls {
		if strings.Contains(c, productup.StackLabel+"=hello") && !strings.Contains(c, "serviceaccounts") {
			t.Fatalf("the stack query leaves out service accounts: %q", c)
		}
	}
}
