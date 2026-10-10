// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package boxvalues offers a product the values of the box itself, such as
// its host name, so no bundle names a box and one bundle fits every box.
// A product's stacks carry a placeholder for each value they read
// (product.yaml box_values: its FQDN, and its Base OS and Base Web
// versions); the box replaces it with its own value
// whenever it puts a stack in front of k0s: k0s-interim at every k0s start
// and productswitch when a switch turns on. The values are recorded on the
// state volume at each product apply and revert, and again when the host
// name changes (docs/network.md#the-host-name).
package boxvalues

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// File keeps the box's values, "<value> <text>" per line, in the platform
// settings directory (/var/lib/sneakers/platform).
const File = "box-values"

// FQDN is the box's name for its product: the host name netd reports (the
// Network setting, else DHCP's name with its domain), else the first
// management address (an IPv6 one in brackets, for URLs), else the box's
// own name. It is lower case, without a trailing dot.
func FQDN(host string, addrs []string, own string) string {
	if h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."); h != "" {
		return h
	}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		if ip.Is6() {
			return "[" + ip.String() + "]"
		}
		return ip.String()
	}
	return own
}

// Pair is one placeholder and the text that replaces it.
type Pair struct{ Placeholder, Text string }

// Table pairs the placeholders the slot's bundle declares
// (productspec.BoxValuesFile) with values; a box.fqdn with no value takes
// kernelHost, the kernel's host name. A placeholder with no text is left
// out, so it stays as it is.
func Table(slot string, values map[string]string, kernelHost string) []Pair {
	f, err := os.Open(filepath.Join(slot, productspec.BoxValuesFile)) // #nosec G304 -- the installed slot's own file
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []Pair
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ph, name, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		v := values[name]
		if v == "" && name == productspec.BoxFQDN {
			v = kernelHost
		}
		if v != "" {
			out = append(out, Pair{Placeholder: ph, Text: v})
		}
	}
	return out
}

// Substitute replaces every placeholder in b with its text. k0s-interim's
// place_stack does the same in shell (os/k0s/boxvalues_test.go).
func Substitute(b []byte, t []Pair) []byte {
	for _, p := range t {
		b = bytes.ReplaceAll(b, []byte(p.Placeholder), []byte(p.Text))
	}
	return b
}

// Read is the values recorded in dir; none when there's no file.
func Read(dir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(dir, File)) // #nosec G304 -- the box's own settings file
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if name, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok && v != "" {
			out[name] = v
		}
	}
	return out
}

// Write records values in dir, through a temporary file and a rename.
func Write(dir string, values map[string]string) error {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s %s\n", n, values[n])
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("boxvalues: %w", err)
	}
	p := filepath.Join(dir, File)
	if err := os.WriteFile(p+".new", []byte(b.String()), 0o644); err != nil { // #nosec G306 -- the box's host name, nothing secret
		return fmt.Errorf("boxvalues: %w", err)
	}
	if err := os.Rename(p+".new", p); err != nil {
		return fmt.Errorf("boxvalues: %w", err)
	}
	return nil
}

// versionRE is what a recorded version may look like: k0s-interim puts it
// into the stacks with sed, so nothing that sed or YAML would read as
// syntax.
var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// RecordVersions records the Base OS version the box runs and the Base Web
// version it serves in dir, next to the values already there. A version
// that doesn't look like one is left out rather than recorded, so its
// placeholder stays and the product shows it as unknown. Init records them
// at every boot, before k0s starts, and osadmin at each product apply and
// revert.
func RecordVersions(dir, osVersion, webVersion string) error {
	values := Read(dir)
	was := maps.Clone(values)
	for name, v := range map[string]string{productspec.BoxOSVersion: osVersion, productspec.BoxWebVersion: webVersion} {
		if versionRE.MatchString(v) {
			values[name] = v
		} else {
			delete(values, name)
		}
	}
	if maps.Equal(was, values) {
		return nil
	}
	return Write(dir, values)
}

// Box is the box's values as the product gets them.
type Box struct {
	// Dir is the platform settings directory (/var/lib/sneakers/platform).
	Dir string
	// Names are netd's host name and the management addresses.
	Names func(ctx context.Context) (host string, addrs []string, err error)
	// Own is the box's own name (internal/boxname).
	Own func() string
	// Versions are the Base OS version the box runs and the Base Web
	// version it serves; nil records none.
	Versions func() (osVersion, webVersion string)
}

// RecordVersions records the box's versions now (RecordVersions).
func (b *Box) RecordVersions() error {
	if b.Versions == nil {
		return nil
	}
	osVersion, webVersion := b.Versions()
	return RecordVersions(b.Dir, osVersion, webVersion)
}

// FQDN is the box's FQDN now.
func (b *Box) FQDN(ctx context.Context) (string, error) {
	host, addrs, err := b.Names(ctx)
	if err != nil {
		return "", fmt.Errorf("boxvalues: the box's names can't be read: %w", err)
	}
	return FQDN(host, addrs, b.Own()), nil
}

// Recorded is the FQDN the product's stacks were last put in place with.
func (b *Box) Recorded() string { return Read(b.Dir)[productspec.BoxFQDN] }

// Ensure records the FQDN now, and says whether it changed. When the names
// can't be read, the recorded one stays.
func (b *Box) Ensure(ctx context.Context) (string, bool, error) {
	fqdn, err := b.FQDN(ctx)
	if err != nil {
		return b.Recorded(), false, err
	}
	values := Read(b.Dir)
	if values[productspec.BoxFQDN] == fqdn {
		return fqdn, false, nil
	}
	values[productspec.BoxFQDN] = fqdn
	if err := Write(b.Dir, values); err != nil {
		return "", false, err
	}
	return fqdn, true, nil
}
