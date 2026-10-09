// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productswitch turns the parts of the installed product its
// product.yaml declares as switches (such as an MCP server) on and off. A
// switch gates its own stacks: k0s applies them only while it's on, and
// takes their objects away when it's turned off. The setting is kept on
// the state volume, so it outlives a reboot, an update and a revert;
// k0s-interim reads it at every k0s start, with the defaults the slot
// records (productspec.SwitchStacksFile).
package productswitch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// StateFile holds the switches an admin set, "<name> on|off" per line, in
// Switches.Dir.
const StateFile = "switches"

// Switches are the installed product's switches on the box.
type Switches struct {
	// Dir is the platform settings directory (/var/lib/sneakers/platform).
	Dir string
	// Slot is the product's current slot.
	Slot string
	// Manifests is k0s's manifests directory (/var/lib/k0s/manifests).
	Manifests string
	// Restart restarts a workload after a change; nil restarts none.
	Restart func(ctx context.Context, ns, kind, name string) error
	Logger  log.Logger
}

func (s *Switches) logger() log.Logger {
	if s.Logger == nil {
		return log.Nop()
	}
	return s.Logger
}

func readState(dir string) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(filepath.Join(dir, StateFile)) // #nosec G304 -- the box's own settings file
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok {
			out[name] = v == "on"
		}
	}
	return out
}

// On reports whether switch name is on, and whether spec declares it.
func (s *Switches) On(spec productspec.Spec, name string) (bool, bool) {
	w, ok := spec.Switch(name)
	if !ok {
		return false, false
	}
	if v, set := readState(s.Dir)[name]; set {
		return v, true
	}
	return w.Default, true
}

// Set turns switch name on or off: the setting is kept, its stacks are put
// in front of k0s or taken away, and its workloads restarted. With k0s not
// running the stacks wait for its next start.
func (s *Switches) Set(ctx context.Context, spec productspec.Spec, name string, on bool) error {
	w, ok := spec.Switch(name)
	if !ok {
		return codes.New(codes.NotAvailable, "the installed product has no switch %q", name)
	}
	st := readState(s.Dir)
	st[name] = on
	if err := writeState(s.Dir, st); err != nil {
		return err
	}
	lg := s.logger()
	lg.Info("productswitch: switch set", log.F("switch", name), log.F("on", on))
	if _, err := os.Stat(s.Manifests); err != nil {
		lg.Info("productswitch: k0s hasn't started; its next start applies the switch", log.F("switch", name))
		return nil
	}
	for _, stack := range w.Stacks {
		if err := s.place(stack, on); err != nil {
			return err
		}
	}
	var errs []error
	for i := range w.Restart {
		ns, kind, n, _ := w.RestartRef(i)
		if s.Restart == nil {
			continue
		}
		if err := s.Restart(ctx, ns, kind, n); err != nil {
			lg.Warn("productswitch: a workload didn't restart; it reads the change at its next start", log.F("workload", w.Restart[i]), log.F("error", err.Error()))
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// place puts the slot's stack in front of k0s, or takes it away.
func (s *Switches) place(stack string, on bool) error {
	dst := filepath.Join(s.Manifests, stack)
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("productswitch: %w", err)
	}
	if !on {
		return nil
	}
	src := filepath.Join(s.Slot, "manifests", stack)
	files, err := filepath.Glob(filepath.Join(src, "*.yaml"))
	if err != nil {
		return fmt.Errorf("productswitch: %w", err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil { // #nosec G301 -- k0s's stack directory, as k0s-interim makes them
		return fmt.Errorf("productswitch: %w", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- the installed slot's own stack
		if err != nil {
			return fmt.Errorf("productswitch: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dst, filepath.Base(f)), b, 0o644); err != nil { // #nosec G306 G703 -- a stack of the installed slot that k0s reads, as k0s-interim copies them
			return fmt.Errorf("productswitch: %w", err)
		}
	}
	return nil
}

func writeState(dir string, st map[string]bool) error {
	names := make([]string, 0, len(st))
	for n := range st {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, n := range names {
		v := "off"
		if st[n] {
			v = "on"
		}
		fmt.Fprintf(&b, "%s %s\n", n, v)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("productswitch: %w", err)
	}
	p := filepath.Join(dir, StateFile)
	if err := os.WriteFile(p+".new", []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("productswitch: %w", err)
	}
	if err := os.Rename(p+".new", p); err != nil {
		return fmt.Errorf("productswitch: %w", err)
	}
	return nil
}

// OffStacks are the slot's switch-gated stacks that are off now: the
// state in dir, else the slot's default. k0s-interim works out the same in
// shell.
func OffStacks(slot, dir string) []string {
	f, err := os.Open(filepath.Join(slot, productspec.SwitchStacksFile)) // #nosec G304 -- the installed slot's own file
	if errors.Is(err, fs.ErrNotExist) || err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	st := readState(dir)
	var off []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) != 3 {
			continue
		}
		on, set := st[parts[0]]
		if !set {
			on = parts[2] == "on"
		}
		if !on {
			off = append(off, parts[1])
		}
	}
	return off
}
