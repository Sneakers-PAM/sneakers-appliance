// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command resrender is the product bundle's resources chart, as the box
// renders it, for the build's tests (build/product/sneakers/render_test.sh):
//
//	resrender render <slot dir>     what the box does when it stages the
//	                                bundle in the slot (product.RenderResources)
//	resrender values <product.yaml> the resources section's values, as a values
//	                                file for the chart on its own
//	resrender docs <rendered.yaml> [chart]
//	                                one line per object of a render (only those
//	                                labelled helm.sh/chart: <chart>-<version>
//	                                with chart given): its kind, name and a hash
//	                                of its text, sorted
//
// render runs the slot's own helm (HELM names another).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: resrender render <slot dir> | values <product.yaml> | docs <rendered.yaml> [chart]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "render":
		err = product.RenderResources(context.Background(), os.Args[2], product.ExecHelm, nil)
	case "values":
		err = values(os.Args[2])
	case "docs":
		chart := ""
		if len(os.Args) == 4 {
			chart = os.Args[3]
		}
		err = docs(os.Args[2], chart)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "resrender:", err)
		os.Exit(1)
	}
}

func values(path string) error {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	spec, err := productspec.Parse(b)
	if err != nil {
		return err
	}
	if spec.Resources == nil {
		return fmt.Errorf("%s has no resources section", path)
	}
	out, err := yaml.Marshal(spec.Resources.Values)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

func docs(path, chart string) error {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	var lines []string
	for _, d := range strings.Split("\n"+string(b), "\n---\n") {
		var o struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(d), &o); err != nil {
			return err
		}
		if o.Kind == "" || (chart != "" && !strings.Contains(d, "helm.sh/chart: "+chart+"-")) {
			continue
		}
		var body []string
		for _, l := range strings.Split(d, "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") && t != "---" {
				body = append(body, l)
			}
		}
		h := sha256.Sum256([]byte(strings.Join(body, "\n")))
		lines = append(lines, fmt.Sprintf("%s/%s %s", o.Kind, o.Metadata.Name, hex.EncodeToString(h[:6])))
	}
	sort.Strings(lines)
	fmt.Println(strings.Join(lines, "\n"))
	return nil
}
