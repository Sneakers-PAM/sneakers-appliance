// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"context"
	"os"
	"slices"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// userRunner is a fakeRunner that can also start a program as a user.
type userRunner struct {
	*fakeRunner
	mu  sync.Mutex
	ids map[string][2]uint32
}

func (r *userRunner) StartAs(argv []string, uid, gid uint32) (services.Process, error) {
	r.mu.Lock()
	r.ids[argv[0]] = [2]uint32{uid, gid}
	r.mu.Unlock()
	return r.Start(argv)
}

func (r *userRunner) idsOf(exec string) ([2]uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.ids[exec]
	return v, ok
}

func table(t *testing.T, files map[string]string) (services.Table, error) {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys["d/"+name+".yaml"] = &fstest.MapFile{Data: []byte(body)}
	}
	return services.Load(fsys, "d")
}

func TestAServiceNamesAFixedSystemUser(t *testing.T) {
	tbl, err := table(t, map[string]string{"web": "exec: /usr/bin/web\nphases: [normal]\nuser: osadmin\n"})
	if err != nil {
		t.Fatal(err)
	}
	if tbl["web"].User != "osadmin" {
		t.Fatalf("user %q", tbl["web"].User)
	}
	for _, u := range []string{"alice", "maint", "nobody-else"} {
		_, err := table(t, map[string]string{"web": "exec: /usr/bin/web\nphases: [normal]\nuser: " + u + "\n"})
		if !codes.Is(err, codes.ServiceTableInvalid) {
			t.Fatalf("user %s: %v", u, err)
		}
	}
}

func TestAServiceWithAUserStartsAsThatUser(t *testing.T) {
	tbl, err := table(t, map[string]string{"web": "exec: /usr/bin/web\nphases: [normal]\nuser: osadmin\n", "root": "exec: /usr/bin/root\nphases: [normal]\n"})
	if err != nil {
		t.Fatal(err)
	}
	r := &userRunner{fakeRunner: newRunner(), ids: map[string][2]uint32{}}
	sup := services.NewSupervisor(r, tbl, opts())
	if err := sup.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	eventually(t, "both started", func() bool { return len(r.starts()) == 2 })
	if ids, ok := r.idsOf("/usr/bin/web"); !ok || ids != [2]uint32{102, 102} {
		t.Fatalf("web ran as %v (%v)", ids, ok)
	}
	if _, ok := r.idsOf("/usr/bin/root"); ok {
		t.Fatal("a service without a user went through StartAs")
	}
}

func TestAServiceWithAUserNeverFallsBackToRoot(t *testing.T) {
	tbl, err := table(t, map[string]string{"web": "exec: /usr/bin/web\nphases: [normal]\nuser: osadmin\nrestart: never\n"})
	if err != nil {
		t.Fatal(err)
	}
	r := newRunner()
	sup := services.NewSupervisor(r, tbl, opts())
	_ = sup.EnterPhase(context.Background(), phase.Normal)
	if slices.Contains(r.starts(), "/usr/bin/web") {
		t.Fatal("a runner that can't change user started the service as root")
	}
}

func TestOnDemandInOnePhaseAlwaysInTheOthers(t *testing.T) {
	tbl, err := table(t, map[string]string{"web": "exec: /usr/bin/web\nphases: [firstboot, normal]\non-demand-in: [firstboot]\n"})
	if err != nil {
		t.Fatal(err)
	}
	r := newRunner()
	sup := services.NewSupervisor(r, tbl, opts())
	ctx := context.Background()
	if err := sup.EnterPhase(ctx, phase.Firstboot); err != nil {
		t.Fatal(err)
	}
	if len(r.starts()) != 0 {
		t.Fatalf("started with firstboot: %v", r.starts())
	}
	if err := sup.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "web on demand", func() bool { return sup.Running("web") })
	if err := sup.Stop("web"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "web stopped", func() bool { return !sup.Running("web") })
	if err := sup.EnterPhase(ctx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	eventually(t, "web with normal", func() bool { return sup.Running("web") })
	if err := sup.Stop("web"); !codes.Is(err, codes.ServiceNotOnDemand) {
		t.Fatalf("stopped an always service in normal: %v", err)
	}
}

func TestOnDemandInMustBeOneOfTheServicesPhases(t *testing.T) {
	for _, body := range []string{
		"exec: /usr/bin/web\nphases: [normal]\non-demand-in: [firstboot]\n",
		"exec: /usr/bin/web\nphases: [firstboot]\nstart: on-demand\non-demand-in: [firstboot]\n",
	} {
		if _, err := table(t, map[string]string{"web": body}); !codes.Is(err, codes.ServiceTableInvalid) {
			t.Fatalf("%q: %v", body, err)
		}
	}
}

// The root image's table: accessd as root in firstboot and normal,
// restarted whenever it stops; osadmin as osadmin after it, on demand
// during first boot.
func TestTheRootImageTable(t *testing.T) {
	tbl, err := services.Load(os.DirFS("../../os/rootfs"), "services.d")
	if err != nil {
		t.Fatal(err)
	}
	a, ok := tbl["accessd"]
	if !ok {
		t.Fatal("no accessd")
	}
	if a.User != "" || a.Restart != services.RestartAlways || a.Start != services.StartAlways || !a.In(phase.Firstboot) || !a.In(phase.Normal) {
		t.Fatalf("accessd: %+v", a)
	}
	o, ok := tbl["osadmin"]
	if !ok {
		t.Fatal("no osadmin")
	}
	if o.User != "osadmin" || o.Restart != services.RestartAlways || !slices.Contains(o.After, "accessd") ||
		!o.In(phase.Firstboot) || !o.In(phase.Normal) || !slices.Equal(o.OnDemandIn, []phase.Phase{phase.Firstboot}) {
		t.Fatalf("osadmin: %+v", o)
	}
}
