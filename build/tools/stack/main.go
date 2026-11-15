// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command stack turns a product's rendered charts into the k0s stacks its
// product bundle carries (build/product/sneakers/render.sh). The conversion
// is internal/stackconv's; this is its flags.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/stackconv"
)

func main() {
	var o stackconv.Options
	var from string
	fl := flag.NewFlagSet("stack", flag.ContinueOnError)
	fl.StringVar(&o.Release, "release", "", "release.yaml, with every image pinned by digest")
	fl.StringVar(&o.ProductYAML, "product-yaml", "", "the product's product.yaml (its box secrets)")
	fl.StringVar(&o.Off, "off", "", "the render with the switch off")
	fl.StringVar(&o.On, "on", "", "the render with the switch on (with -switch-stack)")
	fl.StringVar(&o.Out, "out", "", "the stacks directory: <stack>/<stack>.yaml for each")
	fl.StringVar(&o.Namespace, "namespace", "", "the product's namespace")
	fl.StringVar(&o.Stack, "stack", "", "the always-on stack's name")
	fl.StringVar(&o.SwitchStack, "switch-stack", "", "the switch's stack name; empty for a product without a switch")
	fl.StringVar(&o.SwitchConfigMap, "switch-configmap", "", "the ConfigMap the switch's stack carries")
	fl.StringVar(&from, "switch-from", "", "the ConfigMaps whose changed settings it holds, comma-separated")
	fl.StringVar(&o.Data, "data", "", "the directory the hostPath volumes go under")
	fl.StringVar(&o.WaitJob, "wait-job", "", "the release's Job image whose wait command each phased workload's init container runs")
	if err := fl.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	o.SwitchFrom = strings.Split(from, ",")
	if err := stackconv.Render(o, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "stack:", err)
		os.Exit(1)
	}
}
