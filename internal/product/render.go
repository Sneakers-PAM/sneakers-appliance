// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	log "github.com/Bugs5382/go-log"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/stackconv"
)

// renderTimeout bounds one helm template.
const renderTimeout = 2 * time.Minute

// HelmRunner runs the slot's helm with args and env and answers what it
// printed.
type HelmRunner func(ctx context.Context, helm string, env []string, args ...string) ([]byte, error)

// ExecHelm is the HelmRunner that runs the binary.
func ExecHelm(ctx context.Context, helm string, env []string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, helm, args...) // #nosec G204 -- the slot's own helm, checked against release.yaml's pin
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, bytes.TrimSpace(errb.Bytes()))
	}
	return out.Bytes(), nil
}

// ResourcesStackFile is the file in the phase's stack that holds the chart
// the box rendered, for a product.yaml whose resources name chart.
func ResourcesStackFile(chart string) string { return "resources-" + chart + ".yaml" }

// RenderResources renders the chart the product's resources section names,
// with the slot's own helm, into a file of the phase's stack in the slot
// (docs/resources.md). A product without the section has nothing to render.
// A failed render leaves no file.
func RenderResources(ctx context.Context, dir string, run HelmRunner, lg log.Logger) (err error) {
	if lg == nil {
		lg = log.Nop()
	}
	spec, err := productspec.Load(dir)
	if err != nil {
		return err
	}
	r := spec.Resources
	if r == nil {
		return nil
	}
	lg.Debug("product: rendering the resources chart", log.F("chart", r.Chart), log.F("release", r.Release), log.F("phase", r.Phase))
	b, err := os.ReadFile(filepath.Join(dir, "release.yaml")) // #nosec G304 -- the slot's own file
	if err != nil {
		return fmt.Errorf("product: %w", err)
	}
	rel, err := bundle.ParseRelease(b)
	if err != nil {
		return err
	}
	archive, err := bundle.ChartFile(rel, &spec)
	if err != nil {
		return err
	}
	archive = filepath.Join(dir, filepath.FromSlash(archive))
	if _, err := os.Stat(archive); err != nil { // #nosec G703 -- the archive the bundle check held to release.yaml's pin
		return fmt.Errorf("product: the resources chart %s isn't in the bundle: %w", filepath.Base(archive), err)
	}
	helm := filepath.Join(dir, bundle.ProductHelm)
	if _, err := os.Stat(helm); err != nil {
		return fmt.Errorf("product: the bundle has no helm to render its resources chart with: %w", err)
	}
	var stack string
	for _, p := range spec.Phases {
		if p.Name == r.Phase {
			stack = p.Stack
		}
	}
	// helm keeps its cache and settings in a place it may write, and they
	// are gone once the render is.
	scratch, err := os.MkdirTemp("", "sneakers-render-")
	if err != nil {
		return fmt.Errorf("product: %w", err)
	}
	defer func() { err = errors.Join(err, os.RemoveAll(scratch)) }()
	values, err := yaml.Marshal(r.Values)
	if err != nil {
		return fmt.Errorf("product: the resources values: %w", err)
	}
	valuesFile := filepath.Join(scratch, "values.yaml")
	if err := os.WriteFile(valuesFile, values, 0o600); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HELM_CACHE_HOME=" + filepath.Join(scratch, "cache"),
		"HELM_CONFIG_HOME=" + filepath.Join(scratch, "config"),
		"HELM_DATA_HOME=" + filepath.Join(scratch, "data"),
	}
	ctx, cancel := context.WithTimeout(ctx, renderTimeout)
	defer cancel()
	started := time.Now()
	out, err := run(ctx, helm, env, "template", r.Release, archive, "--namespace", r.Namespace, "--skip-tests", "-f", valuesFile)
	if err != nil {
		lg.Error(err, "product: helm failed on the resources chart", log.F("chart", r.Chart))
		return fmt.Errorf("product: rendering the resources chart %s: %w", r.Chart, err)
	}
	lg.Debug("product: helm rendered the resources chart", log.F("bytes", len(out)), log.F("ms", time.Since(started).Milliseconds()))
	rendered := filepath.Join(scratch, "rendered.yaml")
	if err := os.WriteFile(rendered, out, 0o600); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	dst := filepath.Join(dir, "manifests", stack, ResourcesStackFile(r.Chart))
	if err := stackconv.RenderChart(stackconv.ChartOptions{
		Release: filepath.Join(dir, "release.yaml"), ProductYAML: filepath.Join(dir, productspec.File),
		Rendered: rendered, Namespace: r.Namespace, Phase: r.Phase, Data: r.Data, WaitJob: r.WaitJob, Out: dst,
	}, io.Discard); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("product: converting the resources chart %s: %w", r.Chart, err)
	}
	lg.Info("product: the resources chart is in its phase's stack", log.F("chart", r.Chart), log.F("stack", stack))
	return nil
}
