// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

// The steps a phased product adds (docs/upgrades.md#the-phases): before
// the first phase the box stops what an earlier run left running and
// waits for the cluster's own stacks; each phase is then a step of its
// own, "phase:<name>".
const (
	StepQuiesce     = "quiesce"
	StepCluster     = "cluster"
	PhaseStepPrefix = "phase:"
)

// PlacedFile lists, in the platform settings directory, the stacks the
// phase loop placed in front of k0s; k0s-interim takes them all away at
// the next start, so the phases come up in order again and a slot without
// one of them leaves nothing of it behind.
const PlacedFile = "phase-placed"

// Step is a step of the product coming up, as Updates and the box-state
// stream show it.
type Step struct {
	ID    string
	Label string
}

var stepLabels = map[string]string{
	StepK0s:       "Starting k0s",
	StepImages:    "Importing the images",
	StepManifests: "Applying the product's stacks",
	StepPods:      "Rolling out",
	StepHealth:    "Checking the product's health",
	StepEdge:      "Opening the product on 443",
	StepQuiesce:   "Stopping what was left running",
	StepCluster:   "Starting the cluster's network, DNS and edge",
}

// PhaseStep is the step id of the phase name.
func PhaseStep(name string) string { return PhaseStepPrefix + name }

// IsStep is whether id is a step of the product coming up, phased or not.
func IsStep(id string) bool {
	_, ok := stepLabels[id]
	return ok || strings.HasPrefix(id, PhaseStepPrefix)
}

// Steps are the slot's steps in order: the phased ones when its
// product.yaml declares phases, else Steps.
func (p *Probe) Steps() []Step {
	spec := p.spec()
	if len(spec.Phases) == 0 {
		out := make([]Step, 0, len(Steps))
		for _, id := range Steps {
			out = append(out, Step{ID: id, Label: stepLabels[id]})
		}
		return out
	}
	out := []Step{{StepK0s, stepLabels[StepK0s]}, {StepImages, stepLabels[StepImages]}, {StepQuiesce, stepLabels[StepQuiesce]}, {StepCluster, stepLabels[StepCluster]}}
	for _, ph := range spec.Phases {
		out = append(out, Step{ID: PhaseStep(ph.Name), Label: ph.Label})
	}
	return append(out, Step{StepHealth, stepLabels[StepHealth]}, Step{StepEdge, stepLabels[StepEdge]})
}

// neverStarts are the reasons a container waits that no retry clears: the
// image isn't on the airgapped box, or the pod's spec is wrong. A phase
// with such a pod fails at once.
var neverStarts = map[string]bool{
	"ErrImageNeverPull": true, "InvalidImageName": true, "CreateContainerConfigError": true, "CreateContainerError": true,
}

// checkPhased brings a phased product up one phase at a time and answers
// the first step that isn't done. Every call does at most the next safe
// thing (scale a stopped product's workloads down, place the next stack,
// scale a phase's workloads to the slot's replicas) and answers at once,
// so the caller asks it again every few seconds, on boot and after an
// update or a revert alike.
func (p *Probe) checkPhased(ctx context.Context, spec productspec.Spec) (Result, error) {
	if p.Manifests == "" {
		return Result{}, errors.New("productup: a phased product needs the k0s manifests directory")
	}
	if _, err := p.kubectl(ctx, "get", "--raw", "/readyz"); err != nil {
		return Result{Step: StepK0s, Detail: "The Kubernetes API doesn't answer yet."}, nil
	}
	if have, want, err := p.images(ctx); err != nil {
		return Result{}, err
	} else if have < want {
		return Result{Step: StepImages, Detail: fmt.Sprintf("%d of %d images imported", have, want)}, nil
	}
	on, err := p.onStacks()
	if err != nil {
		return Result{}, err
	}
	phaseStacks := spec.PhaseStacks()
	var always []string
	for _, st := range on {
		if !slices.Contains(phaseStacks, st) {
			always = append(always, st)
		}
	}
	live, err := p.liveWorkloads(ctx)
	if err != nil {
		return Result{}, err
	}
	pods, err := p.podItems(ctx)
	if err != nil {
		return Result{}, err
	}
	alwaysWant, err := p.wantedWorkloads(always)
	if err != nil {
		return Result{}, err
	}
	product, err := p.slotStacks()
	if err != nil {
		return Result{}, err
	}
	if !p.anyPlaced(phaseStacks) {
		if detail, err := p.quiescePass(ctx, live, pods, spec, product, alwaysWant); err != nil {
			return Result{}, err
		} else if detail != "" {
			return Result{Step: StepQuiesce, Detail: detail}, nil
		}
	}
	if missing, err := p.stacks(ctx, always); err != nil {
		return Result{}, err
	} else if len(missing) > 0 {
		return Result{Step: StepCluster, Detail: "Waiting for " + strings.Join(missing, ", ")}, nil
	}
	// The cluster's own workloads (k0s's stacks: CoreDNS, kube-router), and
	// what the always-on stacks declare (the edge); never a product
	// workload, which only its phase starts.
	cluster := func(w workload) bool {
		return w.Metadata.Labels[productspec.PhaseLabel] == "" && !slices.Contains(product, w.Metadata.Labels[StackLabel])
	}
	if waiting := rolloutWith(alwaysWant, live, cluster); waiting != "" {
		return Result{Step: StepCluster, Detail: waiting}, nil
	}
	importOpen := false
	if st, ok := spec.ImportStack(); ok && spec.Import.After != "" {
		importOpen = slices.Contains(on, st)
	}
	for i, ph := range spec.Phases {
		if r, done, err := p.phase(ctx, ph, on, live, pods); err != nil || !done {
			return r, err
		}
		if importOpen && ph.Name == spec.Import.After && i+1 < len(spec.Phases) {
			return p.hold(ctx, spec.Phases[i+1:], live)
		}
	}
	if h := spec.Health(); h != nil {
		if _, err := p.kubectl(ctx, "get", "--raw", "/api/v1/namespaces/"+h.Namespace()+"/services/"+h.ProxyName()+"/proxy"+h.Path); err != nil {
			return Result{Step: StepHealth, Detail: h.Service + " " + h.Path + " doesn't answer ready yet"}, nil
		}
	}
	if p.edgeAnswers(ctx) {
		return Result{}, nil
	}
	return Result{Step: StepEdge, Detail: "443 doesn't answer with the product yet."}, nil
}

// phase moves one phase on: its stacks placed in order, each applied
// before the next, its workloads at the slot's version and replicas, and
// every pod of it Ready. done is true once it is.
func (p *Probe) phase(ctx context.Context, ph productspec.Phase, on []string, live []workload, pods []podItem) (Result, bool, error) {
	at := func(detail string) Result {
		return Result{Step: PhaseStep(ph.Name), Detail: detail, Timeout: ph.TimeoutOrDefault()}
	}
	var stacks []string
	for _, st := range ph.Stacks() {
		if slices.Contains(on, st) {
			stacks = append(stacks, st)
		}
	}
	for _, st := range stacks {
		if _, err := os.Stat(filepath.Join(p.Manifests, st)); err != nil {
			if err := p.place(st); err != nil {
				return Result{}, false, err
			}
			return at("Applying " + st), false, nil
		}
		if missing, err := p.stacks(ctx, []string{st}); err != nil {
			return Result{}, false, err
		} else if len(missing) > 0 {
			return at("Applying " + st), false, nil
		}
	}
	want, err := p.wantedWorkloads(stacks)
	if err != nil {
		return Result{}, false, err
	}
	byKey := map[string]workload{}
	for _, w := range live {
		byKey[w.Kind+" "+w.Metadata.Namespace+"/"+w.Metadata.Name] = w
	}
	for _, w := range want {
		got, ok := byKey[w.key()]
		if !ok || !sameTemplate(w.template, got.Spec.Template) {
			continue
		}
		if have := replicasOf(got); have != w.replicas {
			if err := p.scale(ctx, w.ns, w.kind, w.name, w.replicas); err != nil {
				return Result{}, false, err
			}
			return at(fmt.Sprintf("Starting %s/%s", w.ns, w.name)), false, nil
		}
	}
	ready, total, stopping, why, never := countPods(pods, func(it podItem) bool { return it.Metadata.Labels[productspec.PhaseLabel] == ph.Name })
	if why != "" {
		r := at(fmt.Sprintf("%d of %d pods ready: %s", ready, total, why))
		r.Failed = never
		return r, false, nil
	}
	inPhase := func(w workload) bool { return w.Metadata.Labels[productspec.PhaseLabel] == ph.Name }
	if waiting := rolloutWith(want, live, inPhase); waiting != "" {
		return at(waiting), false, nil
	}
	if total == 0 || ready < total {
		return at(fmt.Sprintf("%d of %d pods ready", ready, total)), false, nil
	}
	if stopping > 0 {
		return at(fmt.Sprintf("%d old %s still stopping", stopping, plural(stopping, "pod", "pods"))), false, nil
	}
	return Result{}, true, nil
}

// hold keeps the phases after an open import's phase stopped: their
// workloads are scaled to 0, and the answer, at the first of them, says
// the product is held until the import is closed.
func (p *Probe) hold(ctx context.Context, later []productspec.Phase, live []workload) (Result, error) {
	names := map[string]bool{}
	for _, ph := range later {
		names[ph.Name] = true
	}
	for _, w := range live {
		if names[w.Metadata.Labels[productspec.PhaseLabel]] && replicasOf(w) > 0 {
			if err := p.scale(ctx, w.Metadata.Namespace, w.Kind, w.Metadata.Name, 0); err != nil {
				return Result{}, err
			}
		}
	}
	return Result{Step: PhaseStep(later[0].Name), Detail: "Held while an import is open; it starts once the import is closed", Held: true}, nil
}

func replicasOf(w workload) int64 {
	if w.Spec.Replicas == nil {
		return 1
	}
	return *w.Spec.Replicas
}

// anyPlaced is whether the phase loop placed any phase stack since k0s
// started (k0s-interim takes them all away before each start).
func (p *Probe) anyPlaced(phaseStacks []string) bool {
	for _, st := range phaseStacks {
		if _, err := os.Stat(filepath.Join(p.Manifests, st)); err == nil {
			return true
		}
	}
	return false
}

// place puts the slot's stack in front of k0s, with the box's values, and
// lists it in PlacedFile.
func (p *Probe) place(stack string) error {
	if err := os.MkdirAll(p.SwitchDir, 0o700); err != nil {
		return fmt.Errorf("productup: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(p.SwitchDir, PlacedFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- the box's own settings file
	if err != nil {
		return fmt.Errorf("productup: %w", err)
	}
	_, werr := fmt.Fprintln(f, stack)
	if err := errors.Join(werr, f.Close()); err != nil {
		return fmt.Errorf("productup: %w", err)
	}
	return productswitch.PlaceStack(p.Slot, p.SwitchDir, p.Manifests, stack)
}

func (p *Probe) scale(ctx context.Context, ns, kind, name string, replicas int64) error {
	_, err := p.kubectl(ctx, "scale", "--namespace", ns, strings.ToLower(kind)+"/"+name, "--replicas="+strconv.FormatInt(replicas, 10))
	return err
}

func (p *Probe) liveWorkloads(ctx context.Context) ([]workload, error) {
	out, err := p.kubectl(ctx, "get", "deployments,statefulsets,daemonsets", "--all-namespaces", "-l", StackLabel, "-o", "json")
	if err != nil {
		return nil, err
	}
	var l workloadList
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, fmt.Errorf("the workload list doesn't parse: %w", err)
	}
	return l.Items, nil
}

func (p *Probe) podItems(ctx context.Context) ([]podItem, error) {
	out, err := p.kubectl(ctx, "get", "pods", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}
	var l podList
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, fmt.Errorf("the pod list doesn't parse: %w", err)
	}
	return l.Items, nil
}

// slotStacks are every stack the slot carries, switched on or off: the
// product's, as opposed to k0s's own.
func (p *Probe) slotStacks() ([]string, error) {
	dirs, err := os.ReadDir(filepath.Join(p.Slot, "manifests"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var out []string
	for _, d := range dirs {
		if d.IsDir() {
			out = append(out, d.Name())
		}
	}
	return out, nil
}

// specs are the slot's product.yaml first, then the staged and the
// previous slots' next to it, the ones an apply or a revert switches to:
// a running product without phases stops in the order of the incoming
// one.
func (p *Probe) specs(first productspec.Spec) []productspec.Spec {
	out := []productspec.Spec{first}
	for _, link := range []string{"staged", "previous"} {
		dir := filepath.Join(filepath.Dir(p.Slot), link)
		if _, err := os.Stat(filepath.Join(dir, productspec.File)); err != nil {
			continue
		}
		if s, err := productspec.Load(dir); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// phaseOf is the order, from 1, of the phase the first of specs that
// names workload puts it in.
func phaseOf(specs []productspec.Spec, workload string) (int, bool) {
	for _, s := range specs {
		if i, ok := s.PhaseOf(workload); ok {
			return i + 1, true
		}
	}
	return 0, false
}

// quiesceTargets are the product's workloads to stop, in groups, in the
// order they stop: the ones no spec names in a phase first (what an
// earlier version left), then each phase, latest first, so the data phase
// stops last, with nothing connected. A workload's phase is its phase-order
// label, else the phase the first of specs (the slot's, then the slots an
// update or a revert switches to) names it in: an update from a bundle
// without phases finds its workloads unlabelled, in its one stack or in
// what are now phase stacks (a switch's included). A workload no spec puts
// in a phase that the always-on stacks declare (the edge), and what isn't
// in the slot's stacks (k0s's own), are never stopped.
func quiesceTargets(live []workload, specs []productspec.Spec, product []string, alwaysWant []wanted) [][]workload {
	declared := map[string]bool{}
	for _, w := range alwaysWant {
		declared[w.key()] = true
	}
	var unnamed []workload
	byOrder := map[int][]workload{}
	for _, w := range live {
		if o, err := strconv.Atoi(w.Metadata.Labels[productspec.PhaseOrderLabel]); err == nil {
			byOrder[o] = append(byOrder[o], w)
			continue
		}
		key := w.Kind + " " + w.Metadata.Namespace + "/" + w.Metadata.Name
		if w.Kind == "DaemonSet" || !slices.Contains(product, w.Metadata.Labels[StackLabel]) {
			continue
		}
		if o, ok := phaseOf(specs, w.Metadata.Name); ok {
			byOrder[o] = append(byOrder[o], w)
			continue
		}
		if !declared[key] {
			unnamed = append(unnamed, w)
		}
	}
	var out [][]workload
	if len(unnamed) > 0 {
		out = append(out, unnamed)
	}
	orders := make([]int, 0, len(byOrder))
	for o := range byOrder {
		orders = append(orders, o)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(orders)))
	for _, o := range orders {
		out = append(out, byOrder[o])
	}
	return out
}

// owners maps each ReplicaSet, "<namespace>/<name>", to the Deployment
// that owns it, so a Deployment's pods are found by owner.
func (p *Probe) owners(ctx context.Context) (map[string]string, error) {
	out, err := p.kubectl(ctx, "get", "replicasets", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}
	var l struct {
		Items []struct {
			Metadata struct {
				Namespace       string     `json:"namespace"`
				Name            string     `json:"name"`
				OwnerReferences []ownerRef `json:"ownerReferences"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, fmt.Errorf("the ReplicaSet list doesn't parse: %w", err)
	}
	m := map[string]string{}
	for _, rs := range l.Items {
		for _, o := range rs.Metadata.OwnerReferences {
			if o.Kind == "Deployment" {
				m[rs.Metadata.Namespace+"/"+rs.Metadata.Name] = o.Name
			}
		}
	}
	return m, nil
}

// ownedBy is whether pod it belongs to workload w: its owner is w (a
// StatefulSet's pods) or a ReplicaSet w owns (a Deployment's).
func ownedBy(it podItem, w workload, rs map[string]string) bool {
	if it.Metadata.Namespace != w.Metadata.Namespace {
		return false
	}
	for _, o := range it.Metadata.OwnerReferences {
		switch {
		case o.Kind == w.Kind && o.Name == w.Metadata.Name:
			return true
		case o.Kind == "ReplicaSet" && w.Kind == "Deployment" && rs[it.Metadata.Namespace+"/"+o.Name] == w.Metadata.Name:
			return true
		}
	}
	return false
}

// stopGroup scales the group's workloads that still run to 0; it answers
// how many it scaled and how many of their pods, found by owner (an
// earlier version's carry no phase labels), are still there.
func (p *Probe) stopGroup(ctx context.Context, group []workload, pods []podItem, rs map[string]string) (scaled, left int, err error) {
	for _, w := range group {
		if replicasOf(w) > 0 {
			if err := p.scale(ctx, w.Metadata.Namespace, w.Kind, w.Metadata.Name, 0); err != nil {
				return scaled, 0, err
			}
			scaled++
		}
		for _, it := range pods {
			if it.Status.Phase != "Succeeded" && it.Status.Phase != "Failed" && ownedBy(it, w, rs) {
				left++
			}
		}
	}
	return scaled, left, nil
}

// quiescePass is the start of every boot and every product restart: what
// an earlier run left running (after a power loss the kubelet restarts
// every container in place, all at once) is scaled to 0 and waited for,
// one group of quiesceTargets at a time, so each phase starts with fresh
// pods and the database stops last. It answers what it waits for, or ""
// once nothing of the product runs.
func (p *Probe) quiescePass(ctx context.Context, live []workload, pods []podItem, spec productspec.Spec, product []string, alwaysWant []wanted) (string, error) {
	groups := quiesceTargets(live, p.specs(spec), product, alwaysWant)
	if len(groups) == 0 {
		return "", nil
	}
	rs, err := p.owners(ctx)
	if err != nil {
		return "", err
	}
	for _, g := range groups {
		scaled, left, err := p.stopGroup(ctx, g, pods, rs)
		if err != nil {
			return "", err
		}
		switch {
		case scaled > 0:
			return fmt.Sprintf("Stopping %d %s an earlier run left running", scaled, plural(scaled, "workload", "workloads")), nil
		case left > 0:
			return fmt.Sprintf("%d %s still stopping", left, plural(left, "pod", "pods")), nil
		}
	}
	return "", nil
}

// QuiesceBound bounds Quiesce as k0s's pre-stop: inside its 5-minute
// stop-timeout, with room for the database's own 2-minute shutdown grace.
const QuiesceBound = 270 * time.Second

// Quiesce stops the product before k0s stops (the k0s service's pre-stop,
// `sneakers-accessd quiesce`), by the slot it runs from: each group of
// quiesceTargets is scaled to 0 and its pods waited for before the next,
// asking every every, so the services stop before the database they use
// and the database stops cleanly with nothing connected. With the API down
// there is nothing to do. ctx bounds it.
func (p *Probe) Quiesce(ctx context.Context, every time.Duration) error {
	if _, err := p.kubectl(ctx, "get", "--raw", "/readyz"); err != nil {
		return nil
	}
	spec := p.spec()
	on, err := p.onStacks()
	if err != nil {
		return err
	}
	var always []string
	for _, st := range on {
		if !slices.Contains(spec.PhaseStacks(), st) {
			always = append(always, st)
		}
	}
	alwaysWant, err := p.wantedWorkloads(always)
	if err != nil {
		return err
	}
	product, err := p.slotStacks()
	if err != nil {
		return err
	}
	live, err := p.liveWorkloads(ctx)
	if err != nil {
		return err
	}
	for _, g := range quiesceTargets(live, p.specs(spec), product, alwaysWant) {
		for {
			pods, err := p.podItems(ctx)
			if err != nil {
				return err
			}
			rs, err := p.owners(ctx)
			if err != nil {
				return err
			}
			_, left, err := p.stopGroup(ctx, g, pods, rs)
			if err != nil {
				return err
			}
			if left == 0 {
				break
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("productup: %d pods still stopping: %w", left, ctx.Err())
			case <-time.After(every):
			}
			if live, err = p.liveWorkloads(ctx); err != nil {
				return err
			}
			g = refresh(g, live)
		}
	}
	return nil
}

// refresh is group with each workload's state from live.
func refresh(group, live []workload) []workload {
	byKey := map[string]workload{}
	for _, w := range live {
		byKey[w.Kind+" "+w.Metadata.Namespace+"/"+w.Metadata.Name] = w
	}
	out := make([]workload, 0, len(group))
	for _, w := range group {
		if now, ok := byKey[w.Kind+" "+w.Metadata.Namespace+"/"+w.Metadata.Name]; ok {
			out = append(out, now)
		}
	}
	return out
}
