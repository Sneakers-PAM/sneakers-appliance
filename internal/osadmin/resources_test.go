// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/resources"
)

const resourcesProduct = `format: 2
phases:
  - {name: data, label: D, stack: s-data, workloads: [old-pg, new-pg]}
  - {name: front, label: F, stack: s-front, workloads: [web]}
data_move:
  label: Moving the database
  after: data
  databases: [app]
  source: {namespace: ns, name: old-pg, host: 127.0.0.1, user: postgres}
  target: {namespace: ns, name: new-pg, host: /var/run/postgresql, user: postgres}
`

const gib = int64(1) << 30

// fakeResources is the cluster as the page sees it.
type fakeResources struct {
	state resources.State
	set   resources.Settings
	nodes int
	err   error
	asked resources.Cluster
}

func (f *fakeResources) State(_ context.Context, c resources.Cluster) (resources.State, error) {
	f.asked = c
	return f.state, f.err
}
func (f *fakeResources) Settings(context.Context, resources.State) (resources.Settings, bool, error) {
	return f.set, false, nil
}
func (f *fakeResources) Nodes(context.Context) (int, error) { return f.nodes, nil }

func newFakeResources() *fakeResources {
	return &fakeResources{
		nodes: 1,
		state: resources.State{
			Replicas:   []resources.Replica{{Name: "new-pg-0", Role: "primary", Healthy: true}},
			Storage:    resources.Storage{SizeBytes: 20 * gib, UsedBytes: gib},
			Parameters: []resources.Parameter{{Name: "work_mem", Value: "4096", Unit: "kB", Default: "4096", Known: true}},
		},
		set: resources.Settings{Replicas: 1, StorageBytes: 20 * gib, Parameters: map[string]string{}, Pools: resources.Pools{DefaultPoolSize: 20, MaxClientConn: 100}},
	}
}

func resourcesBox(t *testing.T, f *fakeResources, spec string) (osadminv1connect.ResourcesServiceClient, *browser) {
	t.Helper()
	b := newBox(t, true, func(_ *box, o *osadmin.Options) { o.Resources = f })
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	if spec != "" {
		if err := os.WriteFile(filepath.Join(b.state, "product", "current", productspec.File), []byte(spec), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return osadminv1connect.NewResourcesServiceClient(alice.hc, b.ts.URL), alice
}

func TestTheResourcesPageShowsTheClusterAndTheSettingsInForce(t *testing.T) {
	f := newFakeResources()
	c, _ := resourcesBox(t, f, resourcesProduct)
	out, err := c.GetResources(context.Background(), connect.NewRequest(&osadminv1.GetResourcesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	m := out.Msg
	if m.GetSettings().GetReplicas() != 1 || m.GetSettings().GetStorageBytes() != 20*gib || m.GetSettings().GetPools().GetDefaultPoolSize() != 20 {
		t.Fatalf("settings %+v", m.GetSettings())
	}
	if len(m.GetReplicas()) != 1 || m.GetReplicas()[0].GetRole() != "primary" || !m.GetReplicas()[0].GetHealthy() {
		t.Fatalf("replicas %+v", m.GetReplicas())
	}
	if m.GetStorage().GetUsedBytes() != gib || m.GetNodes() != 1 || len(m.GetParameters()) != 1 || m.GetParameters()[0].GetName() != "work_mem" || !m.GetParameters()[0].GetKnown() {
		t.Fatalf("%+v", m)
	}
	// The cluster is the one the product's data move targets.
	if f.asked.Namespace != "ns" || f.asked.Name != "new-pg" {
		t.Fatalf("asked %+v", f.asked)
	}
}

func TestPreviewSaysWhatWouldChangeAndRefusesWhatCant(t *testing.T) {
	f := newFakeResources()
	c, _ := resourcesBox(t, f, resourcesProduct)
	ctx := context.Background()
	staged := &osadminv1.ResourceSettings{Replicas: 3, StorageBytes: 40 * gib, Parameters: map[string]string{"shared_buffers": "1GB"}, Pools: &osadminv1.PgBouncerPools{DefaultPoolSize: 20, MaxClientConn: 100}}
	out, err := c.PreviewResources(ctx, connect.NewRequest(&osadminv1.PreviewResourcesRequest{Staged: staged}))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]*osadminv1.ResourceChange{}
	for _, ch := range out.Msg.GetChanges() {
		fields[ch.GetField()] = ch
	}
	if fields["replicas"].GetAfter() != "3" || fields["storage"].GetAfter() != "40Gi" || fields["parameters.shared_buffers"].GetAfter() != "1GB" || !fields["parameters.shared_buffers"].GetRestartRequired() {
		t.Fatalf("%+v", out.Msg.GetChanges())
	}
	if !out.Msg.GetRestartRequired() || len(out.Msg.GetWarnings()) != 1 || !strings.Contains(out.Msg.GetWarnings()[0], "node") {
		t.Fatalf("restart %v, warnings %v", out.Msg.GetRestartRequired(), out.Msg.GetWarnings())
	}
	staged.StorageBytes = 10 * gib
	_, err = c.PreviewResources(ctx, connect.NewRequest(&osadminv1.PreviewResourcesRequest{Staged: staged}))
	symbolIn(t, err, connect.CodeInvalidArgument, "RESOURCES_INVALID")
}

func TestTheResourcesPageIsNotAvailableWithoutAClusterToManage(t *testing.T) {
	for name, spec := range map[string]string{"no data move": "format: 2\n"} {
		c, _ := resourcesBox(t, newFakeResources(), spec)
		_, err := c.GetResources(context.Background(), connect.NewRequest(&osadminv1.GetResourcesRequest{}))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "NOT_AVAILABLE") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No product at all.
	b := newBox(t, true, func(_ *box, o *osadmin.Options) { o.Resources = newFakeResources() })
	alice := b.browser()
	alice.signIn("alice")
	c := osadminv1connect.NewResourcesServiceClient(alice.hc, b.ts.URL)
	if _, err := c.GetResources(context.Background(), connect.NewRequest(&osadminv1.GetResourcesRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("no product: %v", err)
	}
}

func TestAClusterThatCantBeReadIsSaidSoNotShownEmpty(t *testing.T) {
	f := newFakeResources()
	f.err = errors.New("the pod isn't there")
	c, _ := resourcesBox(t, f, resourcesProduct)
	_, err := c.GetResources(context.Background(), connect.NewRequest(&osadminv1.GetResourcesRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "RESOURCES_UNAVAILABLE")
}
