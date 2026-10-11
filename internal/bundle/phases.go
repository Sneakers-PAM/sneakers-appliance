// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// checkPhaseStacks checks that the bundle carries every phase's own stack,
// and that each Deployment, StatefulSet and DaemonSet in a phase's stacks
// is one its phase names and carries the phase's labels on itself and its
// pod template (productspec.PhaseLabel, PhaseOrderLabel), as the render
// puts them: the box finds the product's workloads by them to stop them in
// order.
func checkPhaseStacks(fsys fs.FS, spec productspec.Spec) error {
	if err := checkSwitchStacksPhased(fsys, spec); err != nil {
		return err
	}
	for i, p := range spec.Phases {
		if fi, err := fs.Stat(fsys, path.Join(ProductManifests, p.Stack)); err != nil || !fi.IsDir() {
			return codes.New(codes.KitBundleMismatch, "the product bundle has no stack %s, the phase %s's own", p.Stack, p.Name)
		}
		order := strconv.Itoa(i + 1)
		for _, st := range p.Stacks() {
			files, err := fs.Glob(fsys, path.Join(ProductManifests, st, "*.yaml"))
			if err != nil {
				return codes.New(codes.KitBundleMismatch, "the stack %s can't be read: %v", st, err)
			}
			for _, f := range files {
				if err := checkPhaseFile(fsys, f, st, p, order); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkPhaseFile(fsys fs.FS, file, stack string, p productspec.Phase, order string) error {
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the stack %s can't be read: %v", stack, err)
	}
	type meta struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d struct {
			Kind     string `yaml:"kind"`
			Metadata meta   `yaml:"metadata"`
			Spec     struct {
				Template struct {
					Metadata meta `yaml:"metadata"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return codes.New(codes.KitBundleMismatch, "the stack %s doesn't parse: %v", stack, err)
		}
		switch d.Kind {
		case "Deployment", "StatefulSet", "DaemonSet":
		default:
			continue
		}
		name := d.Metadata.Name
		if !slices.Contains(p.Workloads, name) {
			return codes.New(codes.KitBundleMismatch, "the stack %s holds the %s %s, which its phase %s doesn't name", stack, d.Kind, name, p.Name)
		}
		for _, l := range []map[string]string{d.Metadata.Labels, d.Spec.Template.Metadata.Labels} {
			if l[productspec.PhaseLabel] != p.Name || l[productspec.PhaseOrderLabel] != order {
				return codes.New(codes.KitBundleMismatch, "the %s %s in the stack %s doesn't carry its phase's labels (%s=%s, %s=%s) on itself and its pods", d.Kind, name, stack, productspec.PhaseLabel, p.Name, productspec.PhaseOrderLabel, order)
			}
		}
	}
}

// checkSwitchStacksPhased refuses, in a phased bundle, a switch's stack
// that runs a workload and that no phase places (switch_stacks):
// k0s-interim would place it at k0s's start, ahead of the phases it needs.
func checkSwitchStacksPhased(fsys fs.FS, spec productspec.Spec) error {
	if len(spec.Phases) == 0 {
		return nil
	}
	phased := spec.PhaseStacks()
	for _, w := range spec.Switches {
		for _, st := range w.Stacks {
			if slices.Contains(phased, st) {
				continue
			}
			files, err := fs.Glob(fsys, path.Join(ProductManifests, st, "*.yaml"))
			if err != nil {
				return codes.New(codes.KitBundleMismatch, "the stack %s can't be read: %v", st, err)
			}
			for _, f := range files {
				b, err := fs.ReadFile(fsys, f)
				if err != nil {
					return codes.New(codes.KitBundleMismatch, "the stack %s can't be read: %v", st, err)
				}
				if workloadRE.Match(b) {
					return codes.New(codes.KitBundleMismatch, "the switch %s's stack %s runs a workload, and no phase places it (product.yaml phases switch_stacks)", w.Name, st)
				}
			}
		}
	}
	return nil
}

var workloadRE = regexp.MustCompile(`(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet)\s*$`)
