// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productreset removes the installed product from the box, for the
// closed shell's "<product> reset" (docs/upgrades.md#removing-the-product).
// It works in two steps around k0s stopping, which accessd's osadmin
// backend does in between: Cluster, with k0s up, stops the product in
// order and removes its k0s objects; Data, with k0s stopped, removes its
// data and the box's records of it. It reads the product's stacks from
// the installed slot generically; the product names nothing here, and
// k0s's own stacks and the system namespaces are never touched.
package productreset

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// Reset removes the installed product.
type Reset struct {
	// Slot is the installed product slot, whose k0s answers as kubectl and
	// whose manifests/<stack>/ name the product's stacks.
	Slot string
	// DataDir is k0s's data directory; its admin kubeconfig is
	// pki/admin.conf.
	DataDir string
	// Manifests is k0s's manifests directory (/var/lib/k0s/manifests).
	Manifests string
	// Platform is the platform settings directory
	// (/var/lib/sneakers/platform), which holds the phase loop's list of
	// the stacks it placed.
	Platform string
	// DataRoot is where the product's volumes live
	// (productspec.DataRoot).
	DataRoot string
	// Images is where k0s takes the airgap images from
	// (/var/lib/k0s/images); Products is the slots' directory, which the
	// links there point into.
	Images, Products string
	// Quiesce stops the product in order: its phases in reverse, the
	// database last and cleanly (productup.Probe.Quiesce, the k0s
	// service's pre-stop).
	Quiesce func(ctx context.Context) error
	// Run runs a command and returns its output; nil runs it.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// APIWait bounds the wait for k0s's API to answer, and Every is how
	// often it's asked; 0 is DefaultAPIWait and a second.
	APIWait, Every time.Duration
	Logger         log.Logger
}

// Counts are what a reset removed.
type Counts struct {
	// Namespaces are the product's namespaces; Objects every k0s object
	// removed, the namespaces and what was in them, the stacks'
	// cluster-wide objects and the volumes.
	Namespaces, Objects int
	// Bytes are what the removed files held.
	Bytes int64
}

// DefaultAPIWait is how long the cluster step waits for k0s's API, which
// a k0s that has just started takes to answer.
const DefaultAPIWait = 5 * time.Minute

// DeleteTimeout bounds each delete: a namespace goes once everything in
// it has.
const DeleteTimeout = 5 * time.Minute

// askTimeout bounds each read.
const askTimeout = 30 * time.Second

// The box's own stacks for the product, which accessd and k0s-interim put
// in k0s's manifests beside the slot's: the box secrets, the exposed
// values' RBAC and the edge's certificate.
var boxStacks = []string{productspec.BoxSecretsStack, productspec.RBACStack, "box-tls"}

// systemNamespaces are never removed, whatever a stack puts there.
var systemNamespaces = []string{"default", "kube-system", "kube-public", "kube-node-lease"}

// notRemoved are cluster-wide kinds the reset never deletes: the
// namespaces go on their own, and a node is k0s's.
var notRemoved = []string{"namespaces", "nodes"}

func (r *Reset) logger() log.Logger {
	if r.Logger == nil {
		return log.Nop()
	}
	return r.Logger
}

func (r *Reset) kubectl(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	k0s := filepath.Join(r.Slot, "k0s")
	args = append([]string{"kubectl", "--kubeconfig", filepath.Join(r.DataDir, "pki", "admin.conf")}, args...)
	if r.Run != nil {
		return r.Run(ctx, k0s, args...)
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, k0s, args...) // #nosec G204 -- the installed bundle's k0s, fixed arguments
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("kubectl %s: %w: %s", args[3], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// waitAPI waits until k0s's API answers, within APIWait.
func (r *Reset) waitAPI(ctx context.Context) error {
	wait, every := r.APIWait, r.Every
	if wait <= 0 {
		wait = DefaultAPIWait
	}
	if every <= 0 {
		every = time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		_, err := r.kubectl(ctx, askTimeout, "get", "--raw", "/readyz")
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return codes.New(codes.ProductReset, "k0s's API didn't answer within %s, so the product's objects can't be removed: %v", wait, err)
		}
		select {
		case <-ctx.Done():
			return codes.Wrap(codes.ProductReset, ctx.Err())
		case <-time.After(every):
		}
	}
}

// Stacks are the product's stacks in k0s's manifests, sorted: each the
// installed slot carries, and the box's own for it.
func (r *Reset) Stacks() ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(r.Slot, "manifests"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("productreset: %w", err)
	}
	out := slices.Clone(boxStacks)
	for _, e := range ents {
		if e.IsDir() && !slices.Contains(out, e.Name()) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

// stackDirs are where each stack's files are: the slot's copy, else what
// k0s has.
func (r *Reset) stackDirs(stacks []string) []string {
	var out []string
	for _, st := range stacks {
		out = append(out, filepath.Join(r.Slot, "manifests", st), filepath.Join(r.Manifests, st))
	}
	return out
}

// declaredNamespaces are the namespaces the stacks' files make or put
// objects in, except the system's.
func declaredNamespaces(dirs []string) ([]string, error) {
	var out []string
	add := func(ns string) {
		if ns != "" && !slices.Contains(systemNamespaces, ns) && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.y*ml"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if err := readNamespaces(f, add); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func readNamespaces(file string, add func(string)) error {
	fh, err := os.Open(file) // #nosec G304 -- a stack of the installed slot or k0s's copy of it
	if err != nil {
		return fmt.Errorf("productreset: %w", err)
	}
	defer func() { _ = fh.Close() }()
	dec := yaml.NewDecoder(fh)
	for {
		var d struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		}
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("productreset: %s: %w", file, err)
		}
		if d.Kind == "Namespace" {
			add(d.Metadata.Name)
		}
		add(d.Metadata.Namespace)
	}
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// resources are the kinds the API lists and deletes, namespaced or
// cluster-wide. kubectl answers what it found even when one API group
// doesn't answer.
func (r *Reset) resources(ctx context.Context, namespaced bool) ([]string, error) {
	out, err := r.kubectl(ctx, askTimeout, "api-resources", "--verbs=list,delete", fmt.Sprintf("--namespaced=%t", namespaced), "-o", "name")
	kinds := lines(out)
	if err != nil && len(kinds) == 0 {
		return nil, codes.Wrap(codes.ProductReset, err)
	}
	if err != nil {
		r.logger().Warn("productreset: an API group didn't answer; its kinds aren't counted", log.F("error", err.Error()))
	}
	return kinds, nil
}

// Cluster stops the product in order and removes its k0s objects: its
// stacks leave k0s's manifests (and the phase loop's list of them), so
// nothing applies them again, then its namespaces go with everything in
// them, then its stacks' cluster-wide objects and the volumes its claims
// had. k0s must be running. Nothing is removed until the quiesce is done.
func (r *Reset) Cluster(ctx context.Context) (Counts, error) {
	lg := r.logger()
	stacks, err := r.Stacks()
	if err != nil {
		return Counts{}, err
	}
	namespaces, err := declaredNamespaces(r.stackDirs(stacks))
	if err != nil {
		return Counts{}, codes.Wrap(codes.ProductReset, err)
	}
	lg.Info("productreset: removing the product from k0s", log.F("stacks", strings.Join(stacks, ",")))
	if err := r.waitAPI(ctx); err != nil {
		return Counts{}, err
	}
	started := time.Now()
	if err := r.Quiesce(ctx); err != nil {
		return Counts{}, codes.New(codes.ProductReset, "the product didn't stop in order: %v", err)
	}
	lg.Info("productreset: the product stopped in order", log.F("seconds", int(time.Since(started).Seconds())))
	selector := productup.StackLabel + " in (" + strings.Join(stacks, ",") + ")"
	live, err := r.kubectl(ctx, askTimeout, "get", "namespaces", "-l", selector, "-o", "name")
	if err != nil {
		return Counts{}, codes.Wrap(codes.ProductReset, err)
	}
	for _, l := range lines(live) {
		ns := strings.TrimPrefix(l, "namespace/")
		if !slices.Contains(systemNamespaces, ns) && !slices.Contains(namespaces, ns) {
			namespaces = append(namespaces, ns)
		}
	}
	slices.Sort(namespaces)
	n, cluster, pvs, err := r.count(ctx, namespaces, selector)
	if err != nil {
		return Counts{}, err
	}
	for _, st := range stacks {
		if err := os.RemoveAll(filepath.Join(r.Manifests, st)); err != nil {
			return n, codes.Wrap(codes.ProductReset, err)
		}
	}
	if err := os.Remove(filepath.Join(r.Platform, productup.PlacedFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return n, codes.Wrap(codes.ProductReset, err)
	}
	lg.Info("productreset: the product's stacks are out of k0s's manifests", log.F("stacks", len(stacks)))
	timeout := "--timeout=" + DeleteTimeout.String()
	steps := [][]string{}
	if len(namespaces) > 0 {
		steps = append(steps, append(append([]string{"delete", "namespace"}, namespaces...), "--ignore-not-found", "--wait=true", timeout))
	}
	if len(cluster) > 0 {
		steps = append(steps, []string{"delete", strings.Join(cluster, ","), "-l", selector, "--ignore-not-found", "--wait=true", timeout})
	}
	if len(pvs) > 0 {
		steps = append(steps, append(append([]string{"delete", "pv"}, pvs...), "--ignore-not-found", "--wait=true", timeout))
	}
	for _, args := range steps {
		started := time.Now()
		if _, err := r.kubectl(ctx, DeleteTimeout+time.Minute, args...); err != nil {
			lg.Error(err, "productreset: a delete failed", log.F("what", args[1]))
			return n, codes.New(codes.ProductReset, "the product's %s didn't go: %v", args[1], err)
		}
		lg.Info("productreset: removed", log.F("what", args[1]), log.F("seconds", int(time.Since(started).Seconds())))
	}
	lg.Info("productreset: the product's objects are gone", log.F("namespaces", n.Namespaces), log.F("objects", n.Objects))
	return n, nil
}

// count counts what Cluster removes, and answers the cluster-wide kinds
// to delete by the stacks' label and the volumes the namespaces' claims
// had.
func (r *Reset) count(ctx context.Context, namespaces []string, selector string) (Counts, []string, []string, error) {
	n := Counts{Namespaces: len(namespaces), Objects: len(namespaces)}
	kinds, err := r.resources(ctx, true)
	if err != nil {
		return n, nil, nil, err
	}
	kinds = slices.DeleteFunc(kinds, func(k string) bool { return k == "events" || strings.HasPrefix(k, "events.") })
	for _, ns := range namespaces {
		if len(kinds) == 0 {
			break
		}
		out, err := r.kubectl(ctx, askTimeout, "get", strings.Join(kinds, ","), "-n", ns, "-o", "name", "--ignore-not-found")
		if err != nil && len(out) == 0 {
			return n, nil, nil, codes.Wrap(codes.ProductReset, err)
		}
		n.Objects += len(lines(out))
	}
	cluster, err := r.resources(ctx, false)
	if err != nil {
		return n, nil, nil, err
	}
	cluster = slices.DeleteFunc(cluster, func(k string) bool { return slices.Contains(notRemoved, k) })
	slices.Sort(cluster)
	var labelled []string
	if len(cluster) > 0 {
		out, err := r.kubectl(ctx, askTimeout, "get", strings.Join(cluster, ","), "-l", selector, "-o", "name")
		if err != nil && len(out) == 0 {
			return n, nil, nil, codes.Wrap(codes.ProductReset, err)
		}
		labelled = lines(out)
		n.Objects += len(labelled)
	}
	out, err := r.kubectl(ctx, askTimeout, "get", "pv", "-o", `jsonpath={range .items[*]}{.metadata.name}{" "}{.spec.claimRef.namespace}{"\n"}{end}`)
	if err != nil {
		return n, nil, nil, codes.Wrap(codes.ProductReset, err)
	}
	var pvs []string
	for _, l := range lines(out) {
		name, ns, _ := strings.Cut(l, " ")
		if slices.Contains(namespaces, strings.TrimSpace(ns)) && !slices.Contains(labelled, "persistentvolume/"+name) {
			pvs = append(pvs, name)
		}
	}
	n.Objects += len(pvs)
	return n, cluster, pvs, nil
}

// Data removes, with k0s stopped, everything under DataRoot (the root
// itself stays), each of remove whole (a path that isn't there is
// skipped), and k0s's links to the product's images, which k0s-interim
// links again from the slot at k0s's next start. It answers the bytes the
// removed files held.
func (r *Reset) Data(remove ...string) (int64, error) {
	lg := r.logger()
	var total int64
	ents, err := os.ReadDir(r.DataRoot)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, codes.Wrap(codes.ProductReset, err)
	}
	for _, e := range ents {
		remove = append(remove, filepath.Join(r.DataRoot, e.Name()))
	}
	for _, p := range remove {
		n, err := product.DirBytes(p)
		if err != nil {
			return total, codes.Wrap(codes.ProductReset, err)
		}
		if err := os.RemoveAll(p); err != nil {
			return total, codes.New(codes.ProductReset, "%s didn't go: %v", p, err)
		}
		total += n
		lg.Info("productreset: removed", log.F("path", p), log.F("bytes", n))
	}
	links, err := r.imageLinks()
	if err != nil {
		return total, err
	}
	for _, l := range links {
		if err := os.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return total, codes.Wrap(codes.ProductReset, err)
		}
	}
	lg.Info("productreset: the product's data is gone", log.F("bytes", total), log.F("image_links", len(links)))
	return total, nil
}

// imageLinks are the links in Images that point into Products.
func (r *Reset) imageLinks() ([]string, error) {
	if r.Images == "" || r.Products == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(r.Images)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, codes.Wrap(codes.ProductReset, err)
	}
	prefix := filepath.Clean(r.Products) + string(filepath.Separator)
	var out []string
	for _, e := range ents {
		if e.Type()&fs.ModeSymlink == 0 {
			continue
		}
		p := filepath.Join(r.Images, e.Name())
		t, err := os.Readlink(p)
		if err != nil {
			return nil, codes.Wrap(codes.ProductReset, err)
		}
		if strings.HasPrefix(filepath.Clean(t), prefix) {
			out = append(out, p)
		}
	}
	return out, nil
}
