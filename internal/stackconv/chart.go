// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package stackconv

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// ChartOptions are what RenderChart takes.
type ChartOptions struct {
	Release, ProductYAML string
	// Rendered is helm's render of one chart, a file of YAML documents.
	Rendered string
	// Namespace is the product's namespace, which another stack creates.
	Namespace string
	// Phase is the product.yaml phase whose stack holds the chart. Every
	// workload the chart renders must be one of its workloads.
	Phase string
	// Data is the directory the hostPath volumes go under.
	Data string
	// WaitJob names the release's Job image (spec.jobs) whose `wait`
	// command each workload's init container runs; empty adds none.
	WaitJob string
	// Out is the stack file written.
	Out string
}

// RenderChart converts one chart's render into the one stack file of a
// phase: the same conversion Render gives a product's charts (images by
// digest, hostPath volumes, box secrets only, workloads labelled with the
// phase), for a chart the box renders itself, whole and with no switch.
// It makes no Namespace: the product's always-on stack does.
func RenderChart(c ChartOptions, w io.Writer) error {
	o := options{
		Release: c.Release, ProductYAML: c.ProductYAML, Namespace: c.Namespace,
		Data: c.Data, WaitJob: c.WaitJob,
	}
	rel, pins, spec, box, o, err := prepare(o)
	if err != nil {
		return err
	}
	pi := slices.IndexFunc(spec.Phases, func(p productspec.Phase) bool { return p.Name == c.Phase })
	if pi < 0 {
		return fmt.Errorf("product.yaml has no phase %q", c.Phase)
	}
	images := map[string]bool{}
	docs, err := convert(o, c.Rendered, pins, box, images)
	if err != nil {
		return err
	}
	wait, err := waitImage(o, rel, pins, images)
	if err != nil {
		return err
	}
	label := phaseLabeller(o, spec, wait)
	for _, d := range docs {
		kind, _ := d["kind"].(string)
		if !phasedKinds[kind] {
			continue
		}
		name, _ := dig(d, "metadata")["name"].(string)
		i, err := label(d, kind, name)
		if err != nil {
			return err
		}
		if i != pi {
			return fmt.Errorf("the %s %s belongs to the phase %s, not %s", kind, name, spec.Phases[i].Name, c.Phase)
		}
	}
	if err := write(c.Out, docs); err != nil {
		return err
	}
	list := make([]string, 0, len(images))
	for im := range images {
		list = append(list, im)
	}
	sort.Strings(list)
	_, err = fmt.Fprintf(w, "stack: %s %d objects, %d images\n%s\n", c.Phase, len(docs), len(list), strings.Join(list, "\n"))
	return err
}
