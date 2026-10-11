// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productreset_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// kube is k0s's kubectl as the reset sees it: what it answers, and every
// command line it was given, in order.
type kube struct {
	mu    sync.Mutex
	calls []string
	// down: the API doesn't answer.
	down bool
	// objects are what get -n <namespace> lists, by namespace.
	objects map[string][]string
	// labelled are the stacks' cluster-wide objects get -l lists.
	labelled []string
	// pvs are the volumes, "<name> <claim namespace>".
	pvs []string
	// failDelete fails the namespaces' delete.
	failDelete bool
	// quiesced is set by the fake quiesce, and the first kubectl delete
	// checks it came first.
	quiesced, deletedBeforeQuiesce bool
	stacksAtDelete                 []string
	manifests                      string
}

func (k *kube) run(_ context.Context, name string, args ...string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if filepath.Base(name) != "k0s" || len(args) < 3 || args[0] != "kubectl" || args[1] != "--kubeconfig" {
		return nil, errors.New("not k0s kubectl: " + name + " " + strings.Join(args, " "))
	}
	args = args[3:]
	line := strings.Join(args, " ")
	k.calls = append(k.calls, line)
	if k.down {
		return nil, errors.New("the connection to the server was refused")
	}
	switch {
	case line == "get --raw /readyz":
		return []byte("ok"), nil
	case strings.HasPrefix(line, "api-resources") && slices.Contains(args, "--namespaced=true"):
		return []byte("configmaps\nevents\npods\npersistentvolumeclaims\nsecrets\ndeployments.apps\nevents.events.k8s.io\n"), nil
	case strings.HasPrefix(line, "api-resources") && slices.Contains(args, "--namespaced=false"):
		return []byte("namespaces\npersistentvolumes\nclusterroles.rbac.authorization.k8s.io\ncustomresourcedefinitions.apiextensions.k8s.io\nnodes\n"), nil
	case strings.HasPrefix(line, "get namespaces -l "):
		return []byte("namespace/sneakers\n"), nil
	case strings.HasPrefix(line, "get ") && slices.Contains(args, "-n"):
		if strings.Contains(args[1], "events") {
			return nil, errors.New("events are never counted")
		}
		ns := args[slices.Index(args, "-n")+1]
		return []byte(strings.Join(k.objects[ns], "\n")), nil
	case strings.HasPrefix(line, "get ") && slices.Contains(args, "-l"):
		if strings.Contains(args[1], "namespaces") {
			return nil, errors.New("the namespaces are counted on their own")
		}
		return []byte(strings.Join(k.labelled, "\n")), nil
	case strings.HasPrefix(line, "get pv "):
		return []byte(strings.Join(k.pvs, "\n")), nil
	case strings.HasPrefix(line, "delete "):
		if !k.quiesced {
			k.deletedBeforeQuiesce = true
		}
		if k.stacksAtDelete == nil {
			ents, _ := os.ReadDir(k.manifests)
			k.stacksAtDelete = []string{}
			for _, e := range ents {
				k.stacksAtDelete = append(k.stacksAtDelete, e.Name())
			}
		}
		if k.failDelete && strings.HasPrefix(line, "delete namespace ") {
			return nil, errors.New("timed out waiting for the condition on namespaces/sneakers")
		}
		return nil, nil
	}
	return nil, errors.New("unexpected kubectl " + line)
}

func (k *kube) log() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.calls)
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixture is a box with a product installed: its slot's stacks in k0s's
// manifests next to k0s's own, the box's stacks for it, its data and its
// records.
type fixture struct {
	r            *productreset.Reset
	k            *kube
	root         string
	slot, data   string
	manifests    string
	platform     string
	images       string
	quiesceCalls int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{root: root, slot: filepath.Join(root, "product", "a"), data: filepath.Join(root, "sneakers-data"),
		manifests: filepath.Join(root, "k0s", "manifests"), platform: filepath.Join(root, "platform"), images: filepath.Join(root, "k0s", "images")}
	write(t, filepath.Join(f.slot, "k0s"), "#!/bin/sh\n")
	write(t, filepath.Join(f.slot, "manifests", "sneakers-data", "sneakers-data.yaml"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sneakers\n---\napiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: sneakers-postgres\n  namespace: sneakers\n")
	write(t, filepath.Join(f.slot, "manifests", "edge", "edge.yaml"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sneakers-edge\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: traefik\n  namespace: kube-system\n")
	write(t, filepath.Join(f.slot, "images", "aaaa.tar"), "image")
	for _, st := range []string{"sneakers-data", "edge", productspec.BoxSecretsStack, productspec.RBACStack, "box-tls", "kube-router", "coredns"} {
		write(t, filepath.Join(f.manifests, st, st+".yaml"), "kind: ConfigMap\n")
	}
	write(t, filepath.Join(f.manifests, productspec.RBACStack, "exposed-rbac.yaml"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sneakers-appliance\n")
	write(t, filepath.Join(f.data, "postgres", "pgdata", "PG_VERSION"), "18\n")
	write(t, filepath.Join(f.data, "valkey", "dump.rdb"), strings.Repeat("v", 1000))
	write(t, filepath.Join(f.platform, "phase-placed"), "sneakers-data\n")
	if err := os.MkdirAll(f.images, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.slot, "images", "aaaa.tar"), filepath.Join(f.images, "aaaa.tar")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.images, "k0s-own.tar"), "k0s's own")
	f.k = &kube{manifests: f.manifests, objects: map[string][]string{
		"sneakers":           {"configmap/a", "secret/b", "deployment.apps/sneakers-gateway", "persistentvolumeclaim/data"},
		"sneakers-edge":      {"deployment.apps/traefik"},
		"sneakers-appliance": {"serviceaccount/exposed-values"},
	}, labelled: []string{"customresourcedefinition.apiextensions.k8s.io/widgets.example.org", "clusterrole.rbac.authorization.k8s.io/traefik"},
		pvs: []string{"pv-data sneakers", "pv-other other", "pv-free "}}
	f.r = &productreset.Reset{
		Slot: f.slot, DataDir: filepath.Join(root, "k0s"), Manifests: f.manifests, Platform: f.platform, DataRoot: f.data,
		Images: f.images, Products: filepath.Join(root, "product"),
		Quiesce: func(context.Context) error {
			f.quiesceCalls++
			f.k.mu.Lock()
			f.k.quiesced = true
			f.k.mu.Unlock()
			return nil
		},
		Run: f.k.run, APIWait: 50 * time.Millisecond, Every: time.Millisecond,
	}
	return f
}

// The cluster step stops the product in order first, takes its stacks
// away so k0s doesn't apply them again, then removes its namespaces, its
// stacks' cluster-wide objects and its volumes, and counts them. k0s's
// own stacks and the system namespaces stay.
func TestTheClusterStepQuiescesThenRemovesTheProductsObjects(t *testing.T) {
	f := newFixture(t)
	n, err := f.r.Cluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.quiesceCalls != 1 || f.k.deletedBeforeQuiesce {
		t.Fatalf("quiesced %d times, deleted before the quiesce %v", f.quiesceCalls, f.k.deletedBeforeQuiesce)
	}
	if !slices.Equal(f.k.stacksAtDelete, []string{"coredns", "kube-router"}) {
		t.Fatalf("stacks left when the delete ran: %v", f.k.stacksAtDelete)
	}
	if _, err := os.Stat(filepath.Join(f.platform, "phase-placed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the phase-placed list is still there: %v", err)
	}
	// 3 namespaces; 6 objects in them, 2 cluster-wide, 1 volume, and the
	// namespaces themselves.
	if n.Namespaces != 3 || n.Objects != 12 {
		t.Fatalf("counts %+v", n)
	}
	calls := f.k.log()
	want := []string{
		"delete namespace sneakers sneakers-appliance sneakers-edge --ignore-not-found --wait=true --timeout=5m0s",
		"delete clusterroles.rbac.authorization.k8s.io,customresourcedefinitions.apiextensions.k8s.io,persistentvolumes -l k0s.k0sproject.io/stack in (box-tls,edge,sneakers-appliance-exposed,sneakers-appliance-secrets,sneakers-data) --ignore-not-found --wait=true --timeout=5m0s",
		"delete pv pv-data --ignore-not-found --wait=true --timeout=5m0s",
	}
	var deletes []string
	for _, c := range calls {
		if strings.HasPrefix(c, "delete ") {
			deletes = append(deletes, c)
		}
		if strings.Contains(c, "kube-system") || strings.Contains(c, "delete") && strings.Contains(c, "nodes") {
			t.Fatalf("the reset touched the system: %s", c)
		}
	}
	if !slices.Equal(deletes, want) {
		t.Fatalf("deletes:\n%s\nwant:\n%s", strings.Join(deletes, "\n"), strings.Join(want, "\n"))
	}
}

// With k0s's API down the step waits for it, then fails PRODUCT_RESET
// before anything is taken away, so the reset can run again.
func TestTheClusterStepNeedsTheAPI(t *testing.T) {
	f := newFixture(t)
	f.k.down = true
	_, err := f.r.Cluster(context.Background())
	if !codes.Is(err, codes.ProductReset) || !strings.Contains(codes.Describe(err), "k0s") {
		t.Fatalf("want PRODUCT_RESET naming k0s, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.manifests, "sneakers-data")); err != nil {
		t.Fatalf("a stack went with the API down: %v", err)
	}
	if f.quiesceCalls != 0 {
		t.Fatal("quiesced with the API down")
	}
}

// A delete that fails is PRODUCT_RESET with kubectl's reason.
func TestAFailedDeleteSaysWhy(t *testing.T) {
	f := newFixture(t)
	f.k.failDelete = true
	_, err := f.r.Cluster(context.Background())
	if !codes.Is(err, codes.ProductReset) || !strings.Contains(codes.Describe(err), "timed out") {
		t.Fatalf("got %v", err)
	}
}

// A quiesce that fails stops the reset before anything is removed.
func TestAFailedQuiesceRemovesNothing(t *testing.T) {
	f := newFixture(t)
	f.r.Quiesce = func(context.Context) error { return errors.New("2 pods still stopping") }
	_, err := f.r.Cluster(context.Background())
	if !codes.Is(err, codes.ProductReset) || !strings.Contains(codes.Describe(err), "2 pods still stopping") {
		t.Fatalf("got %v", err)
	}
	for _, c := range f.k.log() {
		if strings.HasPrefix(c, "delete ") {
			t.Fatalf("deleted after a failed quiesce: %s", c)
		}
	}
	if _, err := os.Stat(filepath.Join(f.manifests, "sneakers-data")); err != nil {
		t.Fatalf("a stack went after a failed quiesce: %v", err)
	}
}

// The data step, with k0s stopped, removes everything under the data root
// (the root itself stays), the records it's given, and the image links
// into the product's slots, and counts the bytes. k0s's own files stay.
func TestTheDataStepRemovesTheProductsDataAndRecords(t *testing.T) {
	f := newFixture(t)
	secrets := filepath.Join(f.platform, "box-secrets.json")
	write(t, secrets, `{"sneakers/sneakers-box/VAULT_ROOT_KEK":"x"}`)
	exposed := filepath.Join(f.root, "osadmin-api", "exposed")
	write(t, filepath.Join(exposed, "sneakers-setup-token.consumed"), "")
	kept := filepath.Join(f.platform, "box-values")
	write(t, kept, "box.fqdn box1.sneakers.example.org\n")
	n, err := f.r.Data(secrets, exposed, filepath.Join(f.platform, "no-such-file"))
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(3 + 1000 + len(`{"sneakers/sneakers-box/VAULT_ROOT_KEK":"x"}`)); n != want {
		t.Fatalf("removed %d bytes, want %d", n, want)
	}
	if ents, err := os.ReadDir(f.data); err != nil || len(ents) != 0 {
		t.Fatalf("the data root: %v, %v", ents, err)
	}
	for _, p := range []string{secrets, exposed, filepath.Join(f.images, "aaaa.tar")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is still there: %v", p, err)
		}
	}
	for _, p := range []string{kept, filepath.Join(f.images, "k0s-own.tar"), filepath.Join(f.slot, "images", "aaaa.tar")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s went: %v", p, err)
		}
	}
}
