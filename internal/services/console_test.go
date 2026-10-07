// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// consoleRunner is a fakeRunner that can also start a program with its
// standard output on the console's own pipe.
type consoleRunner struct {
	*fakeRunner
	mu     sync.Mutex
	stdout map[string]*os.File
}

func (r *consoleRunner) StartConsole(argv []string, stdout *os.File) (services.Process, error) {
	r.mu.Lock()
	r.stdout[argv[0]] = stdout
	r.mu.Unlock()
	return r.Start(argv)
}

// owner hands out the write end of a pipe per claim and keeps the read
// end, as init's console does.
type owner struct {
	mu     sync.Mutex
	claims int
	reads  []*os.File
}

func (o *owner) Claim() (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.claims++
	o.reads = append(o.reads, r)
	o.mu.Unlock()
	return w, nil
}

// A service marked console gets the console to itself: its standard output
// is a fresh claim on the consoles, which the supervisor closes on its own
// side once the program has it. Other services keep the shared output.
func TestAConsoleServiceOwnsTheConsole(t *testing.T) {
	tbl, err := table(t, map[string]string{
		"console": "exec: /usr/bin/sneakers-console\nphases: [normal]\nconsole: true\nrestart: always\n",
		"accessd": "exec: /usr/bin/sneakers-accessd\nphases: [normal]\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &consoleRunner{fakeRunner: newRunner(), stdout: map[string]*os.File{}}
	o := &owner{}
	opt := opts()
	opt.Console = o
	s := services.NewSupervisor(r, tbl, opt)
	if err := s.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	w, ok := r.stdout["/usr/bin/sneakers-console"]
	_, other := r.stdout["/usr/bin/sneakers-accessd"]
	r.mu.Unlock()
	if !ok || other || o.claims != 1 {
		t.Fatalf("console stdout %v, accessd's %v, claims %d", ok, other, o.claims)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("the supervisor kept its copy of the console's pipe open")
	}
	r.proc("/usr/bin/sneakers-console").crash()
	eventually(t, "a second claim on restart", func() bool { o.mu.Lock(); defer o.mu.Unlock(); return o.claims == 2 })
}

// Without a console to claim (init kept the kernel's), a console service
// starts like any other.
func TestAConsoleServiceWithoutAConsole(t *testing.T) {
	tbl, err := table(t, map[string]string{"console": "exec: /usr/bin/sneakers-console\nphases: [normal]\nconsole: true\n"})
	if err != nil {
		t.Fatal(err)
	}
	r := &consoleRunner{fakeRunner: newRunner(), stdout: map[string]*os.File{}}
	s := services.NewSupervisor(r, tbl, opts())
	if err := s.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	if !s.Running("console") || len(r.stdout) != 0 {
		t.Fatalf("running %v, console starts %d", s.Running("console"), len(r.stdout))
	}
}

// One program owns the console in a phase; two would fight over it.
func TestOnlyOneConsoleServicePerPhase(t *testing.T) {
	_, err := table(t, map[string]string{
		"console":   "exec: /a\nphases: [firstboot, normal]\nconsole: true\n",
		"firstboot": "exec: /b\nphases: [firstboot]\nconsole: true\n",
	})
	if !codes.Is(err, codes.ServiceTableInvalid) {
		t.Fatalf("err = %v", err)
	}
	_, err = table(t, map[string]string{
		"console":   "exec: /a\nphases: [normal]\nconsole: true\n",
		"firstboot": "exec: /b\nphases: [firstboot]\nconsole: true\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = table(t, map[string]string{"console": "exec: /a\nphases: [normal]\nconsole: true\nuser: osadmin\n"})
	if !codes.Is(err, codes.ServiceTableInvalid) {
		t.Fatalf("a console service under a user: %v", err)
	}
}

// The root image's console owners: the dashboard in normal, the wizard in
// first boot, each after accessd and restarted whenever it stops.
func TestTheRootImageConsoleOwners(t *testing.T) {
	tbl, err := services.Load(os.DirFS("../../os/rootfs"), "services.d")
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]phase.Phase{"console": phase.Normal, "firstboot": phase.Firstboot} {
		s, ok := tbl[name]
		if !ok {
			t.Fatalf("no %s", name)
		}
		if !s.Console || len(s.Phases) != 1 || s.Phases[0] != p || s.Restart != services.RestartAlways || s.User != "" || s.OnDemand(p) || len(s.After) != 1 || s.After[0] != "accessd" {
			t.Fatalf("%s: %+v", name, s)
		}
	}
}
