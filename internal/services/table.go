// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package services is init's service table and its supervisor. Init is the
// only supervisor on the box; there's no systemd. Each service is one YAML
// file in /usr/lib/sneakers/services.d/ in the read-only root.
package services

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

// Dir is where the table lives in the root image.
const Dir = "usr/lib/sneakers/services.d"

// Restart policies.
const (
	RestartAlways    = "always"
	RestartOnFailure = "on-failure"
	RestartNever     = "never"
)

// Start modes.
const (
	StartAlways   = "always"
	StartOnDemand = "on-demand"
)

// Service is one entry of the table.
type Service struct {
	Name string `yaml:"-"`
	// Exec and Args are the program and its arguments.
	Exec string   `yaml:"exec"`
	Args []string `yaml:"args"`
	// Phases the service runs in.
	Phases []phase.Phase `yaml:"phases"`
	// After names services that must be ready before this one starts.
	After []string `yaml:"after"`
	// Restart is always, on-failure (the default) or never.
	Restart string `yaml:"restart"`
	// Readiness says when the service counts as ready.
	Readiness Readiness `yaml:"readiness"`
	// Start is always (the default: started on entering its phases) or
	// on-demand (started only through Services.Start).
	Start string `yaml:"start"`
	// PreStart runs to completion before every start; a non-zero exit
	// keeps the service from starting.
	PreStart []string `yaml:"pre-start"`
	// StopTimeout is how long the service gets after SIGTERM before
	// SIGKILL; zero means the supervisor's default. k0s needs longer than
	// most to stop its workloads cleanly.
	StopTimeout time.Duration `yaml:"stop-timeout"`
	// User is a fixed system account (accounts' table) to run as; empty
	// runs as root. A runner that can't change user refuses to start it.
	User string `yaml:"user"`
	// OnDemandIn lists phases, among Phases, in which an always-start
	// service starts only through Services.Start (osadmin waits for its
	// first-boot step).
	OnDemandIn []phase.Phase `yaml:"on-demand-in"`
	// StartWhen lists absolute paths that must all exist before the
	// service starts with its phase. Until they do it waits (Status says
	// SERVICE_WAITING and names the missing path), and the supervisor
	// starts it once they appear. Services.Start starts it at once,
	// whatever the paths, and Services.Stop holds it stopped until the
	// next Start. Only for start: always.
	StartWhen []string `yaml:"start-when"`
	// Console marks the program that owns the consoles in its phases (the
	// dashboard, the setup wizard): its standard output goes to every
	// console and everyone else's goes aside. At most one per phase; it
	// runs as root.
	Console bool `yaml:"console"`
	// Capabilities are the ambient capabilities a service with a user
	// keeps: only net-bind-service, for the edge fallback's 80 and 443.
	Capabilities []string `yaml:"capabilities"`
}

// capabilityBits are the capabilities a service may keep, by name.
var capabilityBits = map[string]uintptr{
	"net-bind-service": 10, // CAP_NET_BIND_SERVICE
}

// Caps is s's ambient capabilities, as capability numbers.
func (s *Service) Caps() []uintptr {
	var out []uintptr
	for _, c := range s.Capabilities {
		out = append(out, capabilityBits[c])
	}
	return out
}

// Readiness is one probe: a file that appears, or a command that exits 0.
// With neither, the service is ready once it has started.
type Readiness struct {
	File    string        `yaml:"file"`
	Exec    []string      `yaml:"exec"`
	Timeout time.Duration `yaml:"timeout"`
}

// Table is the loaded table, by name.
type Table map[string]*Service

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Load reads every <name>.yaml in dir of fsys.
func Load(fsys fs.FS, dir string) (Table, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, codes.New(codes.ServiceTableInvalid, "read %s: %v", dir, err)
	}
	t := Table{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, codes.New(codes.ServiceTableInvalid, "read %s: %v", e.Name(), err)
		}
		s, err := parse(name, b)
		if err != nil {
			return nil, err
		}
		t[name] = s
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	return t, nil
}

func parse(name string, b []byte) (*Service, error) {
	if !nameRE.MatchString(name) {
		return nil, codes.New(codes.ServiceTableInvalid, "%q isn't a valid service name", name)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var s Service
	if err := dec.Decode(&s); err != nil {
		return nil, codes.New(codes.ServiceTableInvalid, "%s.yaml: %v", name, err)
	}
	s.Name = name
	if s.Restart == "" {
		s.Restart = RestartOnFailure
	}
	if s.Start == "" {
		s.Start = StartAlways
	}
	switch {
	case !path.IsAbs(s.Exec):
		return nil, codes.New(codes.ServiceTableInvalid, "%s: exec %q must be an absolute path", name, s.Exec)
	case len(s.Phases) == 0:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: lists no phases", name)
	case s.Restart != RestartAlways && s.Restart != RestartOnFailure && s.Restart != RestartNever:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: restart %q", name, s.Restart)
	case s.Start != StartAlways && s.Start != StartOnDemand:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: start %q", name, s.Start)
	case s.Readiness.File != "" && len(s.Readiness.Exec) > 0:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: readiness takes a file or an exec, not both", name)
	case s.StopTimeout < 0:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: stop-timeout %v", name, s.StopTimeout)
	case len(s.PreStart) > 0 && !path.IsAbs(s.PreStart[0]):
		return nil, codes.New(codes.ServiceTableInvalid, "%s: pre-start %q must be an absolute path", name, s.PreStart[0])
	case len(s.OnDemandIn) > 0 && s.Start != StartAlways:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: on-demand-in needs start: always", name)
	case len(s.StartWhen) > 0 && s.Start != StartAlways:
		return nil, codes.New(codes.ServiceTableInvalid, "%s: start-when needs start: always", name)
	case s.Console && s.User != "":
		return nil, codes.New(codes.ServiceTableInvalid, "%s: a console service runs as root", name)
	}
	if len(s.Capabilities) > 0 && s.User == "" {
		return nil, codes.New(codes.ServiceTableInvalid, "%s: capabilities need a user; root has them all", name)
	}
	for _, c := range s.Capabilities {
		if _, ok := capabilityBits[c]; !ok {
			return nil, codes.New(codes.ServiceTableInvalid, "%s: capability %q isn't one a service may keep", name, c)
		}
	}
	if s.User != "" {
		if _, ok := accounts.ServiceUser(s.User); !ok {
			return nil, codes.New(codes.ServiceTableInvalid, "%s: user %q isn't a fixed unprivileged system account", name, s.User)
		}
	}
	for _, p := range s.StartWhen {
		if !path.IsAbs(p) {
			return nil, codes.New(codes.ServiceTableInvalid, "%s: start-when %q must be an absolute path", name, p)
		}
	}
	for _, p := range s.OnDemandIn {
		if !s.In(p) {
			return nil, codes.New(codes.ServiceTableInvalid, "%s: on-demand-in %q isn't one of its phases", name, p)
		}
	}
	for _, p := range s.Phases {
		switch p {
		case phase.Install, phase.Enrol, phase.Firstboot, phase.Normal:
		default:
			return nil, codes.New(codes.ServiceTableInvalid, "%s: phase %q", name, p)
		}
	}
	return &s, nil
}

// check refuses unknown or cyclic After references, and two console
// services in one phase.
func (t Table) check() error {
	owner := map[phase.Phase]string{}
	for _, n := range t.Names() {
		if s := t[n]; s.Console {
			for _, p := range s.Phases {
				if o, taken := owner[p]; taken {
					return codes.New(codes.ServiceTableInvalid, "%s and %s both own the console in phase %s", o, n, p)
				}
				owner[p] = n
			}
		}
	}
	for _, s := range t {
		for _, a := range s.After {
			if _, ok := t[a]; !ok {
				return codes.New(codes.ServiceTableInvalid, "%s runs after %s, which the table doesn't have", s.Name, a)
			}
		}
	}
	_, err := t.order(t.Names())
	return err
}

// Names lists the services, sorted.
func (t Table) Names() []string {
	out := make([]string, 0, len(t))
	for n := range t {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// order sorts names so every service comes after the ones it names in
// After (among names), stably by name otherwise.
func (t Table) order(names []string) ([]string, error) {
	in := map[string]bool{}
	for _, n := range names {
		in[n] = true
	}
	var out []string
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(n string, trail []string) error
	visit = func(n string, trail []string) error {
		switch state[n] {
		case 1:
			return codes.New(codes.ServiceTableInvalid, "the after: chain %s loops", strings.Join(append(trail, n), " -> "))
		case 2:
			return nil
		}
		state[n] = 1
		deps := append([]string(nil), t[n].After...)
		sort.Strings(deps)
		for _, d := range deps {
			if in[d] {
				if err := visit(d, append(trail, n)); err != nil {
					return err
				}
			}
		}
		state[n] = 2
		out = append(out, n)
		return nil
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for _, n := range sorted {
		if err := visit(n, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// OnDemand reports whether s starts only through Services.Start in p.
func (s *Service) OnDemand(p phase.Phase) bool {
	return s.Start == StartOnDemand || slices.Contains(s.OnDemandIn, p)
}

// Gated reports whether s waits for its start-when paths in p. A gated
// service is also started and stopped through the Services API.
func (s *Service) Gated(p phase.Phase) bool { return len(s.StartWhen) > 0 && !s.OnDemand(p) }

// In reports whether s runs in p.
func (s *Service) In(p phase.Phase) bool {
	for _, q := range s.Phases {
		if q == p {
			return true
		}
	}
	return false
}

func (s *Service) String() string { return fmt.Sprintf("%s (%s)", s.Name, s.Exec) }
