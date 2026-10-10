// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// phasedKinds are the workloads a phase orders.
var phasedKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true}

// phaseSplit takes each workload of the always-on render out into its
// phase's stack, and labels every workload of both renders with its
// phase: on the workload, so the box finds the product's workloads by
// phase when it stops them, and on its pods, so it can wait for them to
// go. Without phases the renders are left as they are.
func phaseSplit(o options, spec productspec.Spec, offDocs, switchDocs []doc) ([]doc, map[string][]doc, error) {
	if len(spec.Phases) == 0 {
		return offDocs, nil, nil
	}
	label := func(d doc, kind, name string) (int, error) {
		i, ok := spec.PhaseOf(name)
		if !ok {
			return 0, fmt.Errorf("the %s %s is in no phase: product.yaml's phases name every workload, so nothing starts unordered", kind, name)
		}
		l := map[string]any{productspec.PhaseLabel: spec.Phases[i].Name, productspec.PhaseOrderLabel: strconv.Itoa(i + 1)}
		addLabels(dig(d, "metadata"), l)
		tmpl := dig(d, "spec", "template")
		if tmpl == nil {
			return 0, fmt.Errorf("the %s %s has no pod template", kind, name)
		}
		if tmpl["metadata"] == nil {
			tmpl["metadata"] = doc{}
		}
		addLabels(dig(tmpl, "metadata"), l)
		return i, nil
	}
	phased := map[string][]doc{}
	var rest []doc
	for _, d := range offDocs {
		kind, _ := d["kind"].(string)
		if !phasedKinds[kind] {
			rest = append(rest, d)
			continue
		}
		name, _ := dig(d, "metadata")["name"].(string)
		i, err := label(d, kind, name)
		if err != nil {
			return nil, nil, err
		}
		phased[spec.Phases[i].Stack] = append(phased[spec.Phases[i].Stack], d)
	}
	for _, d := range switchDocs {
		kind, _ := d["kind"].(string)
		if !phasedKinds[kind] {
			continue
		}
		name, _ := dig(d, "metadata")["name"].(string)
		i, err := label(d, kind, name)
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(spec.Phases[i].SwitchStacks, o.SwitchStack) {
			return nil, nil, fmt.Errorf("the %s %s is in the switch's stack %s, which its phase %s doesn't place (switch_stacks)", kind, name, o.SwitchStack, spec.Phases[i].Name)
		}
	}
	return rest, phased, nil
}

func addLabels(md doc, l map[string]any) {
	have, _ := md["labels"].(doc)
	if have == nil {
		have = doc{}
		md["labels"] = have
	}
	for k, v := range l {
		have[k] = v
	}
}
