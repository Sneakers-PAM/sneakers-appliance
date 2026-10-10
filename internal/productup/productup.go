// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productup tells how far the installed product has come up after
// a product apply or revert restarted k0s: k0s's API answers, the bundle's
// images are imported, its stacks are applied, every workload in them runs
// the slot's version and has rolled out, the product's own health check
// answers, and the edge answers 443 with the product, not the box-state
// page. accessd's osadmin backend (root) asks it every few seconds and
// shows the answer as the update's steps (docs/upgrades.md). It reads the
// stacks and their workloads generically; the product names nothing here.
package productup

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

// The steps, in the order the product comes up, as UpgradeStep.id names
// them.
const (
	StepK0s       = "k0s"
	StepImages    = "images"
	StepManifests = "manifests"
	StepPods      = "pods"
	StepHealth    = "product_health"
	StepEdge      = "edge"
)

// Steps are every step, in order.
var Steps = []string{StepK0s, StepImages, StepManifests, StepPods, StepHealth, StepEdge}

// Result is the first step that isn't done, with what it waits for; Step
// is empty once the product answers on 443.
type Result struct {
	Step   string
	Detail string
	// Timeout is how long the step may take, for a phase step (its
	// product.yaml timeout); 0 is no bound of its own.
	Timeout time.Duration
	// Failed is a phase that can't come up whatever the wait: a pod of it
	// waits for a reason no retry clears (its image isn't on the box, its
	// spec is wrong). Detail names it.
	Failed bool
	// Held is a phased product held after the phase its import names
	// while an import is open (productspec.Import.After): the phases
	// through it run, the later ones wait, and the box says maintenance.
	Held bool
}

// StackLabel is the label k0s's manifest applier puts on every object of a
// stack, valued by the stack's directory name.
const StackLabel = "k0s.k0sproject.io/stack"

// StateHeader is edgefall's header on its box-state page; an answer
// without it comes from the product's edge.
const StateHeader = "Sneakers-Box-State"

// Probe asks k0s and the edge on the box.
type Probe struct {
	// Slot is the current product slot (/var/lib/sneakers/product/current),
	// which holds k0s, images/<hex>.tar and manifests/<stack>/.
	Slot string
	// DataDir is k0s's data directory; its admin kubeconfig is
	// pki/admin.conf.
	DataDir string
	// Containerd is k0s's containerd socket.
	Containerd string
	// Edge is the address 443 is asked on, 127.0.0.1:443.
	Edge string
	// Run runs a command and returns its output; nil runs it.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// HTTP asks the edge; nil is a client that accepts the box's own
	// certificate (on loopback only the answer's source matters).
	HTTP *http.Client
	// SwitchDir holds the product's switch settings
	// (/var/lib/sneakers/platform); a stack whose switch is off isn't
	// applied, so it isn't waited for. The phase loop keeps PlacedFile
	// there.
	SwitchDir string
	// Manifests is k0s's manifests directory (/var/lib/k0s/manifests),
	// where a phased product's phase loop places each phase's stacks.
	Manifests string
}

// askTimeout bounds each command and the edge request.
const askTimeout = 10 * time.Second

func (p *Probe) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, askTimeout)
	defer cancel()
	k0s := filepath.Join(p.Slot, "k0s")
	if p.Run != nil {
		return p.Run(ctx, k0s, args...)
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, k0s, args...) // #nosec G204 -- the installed bundle's k0s, fixed arguments
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("k0s %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (p *Probe) kubectl(ctx context.Context, args ...string) ([]byte, error) {
	return p.run(ctx, append([]string{"kubectl", "--kubeconfig", filepath.Join(p.DataDir, "pki", "admin.conf")}, args...)...)
}

// Check answers the first step that isn't done. The edge answering isn't
// proof on its own: on an update over a running product the old pods keep
// answering while they drain, and right after the restart k0s hasn't
// applied the new slot's stacks yet, so the old workloads look rolled out.
// Every workload in the slot's stacks must run the slot's version and have
// rolled out, no old pod may still be stopping, and the product's own
// health check must answer before it counts.
func (p *Probe) Check(ctx context.Context) (Result, error) {
	if spec := p.spec(); len(spec.Phases) > 0 {
		return p.checkPhased(ctx, spec)
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
	if missing, err := p.stacks(ctx, on); err != nil {
		return Result{}, err
	} else if len(missing) > 0 {
		return Result{Step: StepManifests, Detail: "Waiting for " + strings.Join(missing, ", ")}, nil
	}
	if waiting, err := p.rollout(ctx, on); err != nil {
		return Result{}, err
	} else if waiting != "" {
		return Result{Step: StepPods, Detail: waiting}, nil
	}
	ready, total, stopping, why, err := p.pods(ctx)
	if err != nil {
		return Result{}, err
	}
	if total == 0 || ready < total {
		d := fmt.Sprintf("%d of %d pods ready", ready, total)
		if why != "" {
			d += ": " + why
		}
		return Result{Step: StepPods, Detail: d}, nil
	}
	if stopping > 0 {
		return Result{Step: StepPods, Detail: fmt.Sprintf("%d old %s still stopping", stopping, plural(stopping, "pod", "pods"))}, nil
	}
	if h := p.spec().Health(); h != nil {
		if _, err := p.kubectl(ctx, "get", "--raw", "/api/v1/namespaces/"+h.Namespace()+"/services/"+h.ProxyName()+"/proxy"+h.Path); err != nil {
			return Result{Step: StepHealth, Detail: h.Service + " " + h.Path + " doesn't answer ready yet"}, nil
		}
	}
	if p.edgeAnswers(ctx) {
		return Result{}, nil
	}
	return Result{Step: StepEdge, Detail: "443 doesn't answer with the product yet."}, nil
}

// spec is the slot's product.yaml; one that doesn't read declares nothing.
func (p *Probe) spec() productspec.Spec {
	s, err := productspec.Load(p.Slot)
	if err != nil {
		return productspec.Spec{}
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

type container struct {
	Name    string   `json:"name" yaml:"name"`
	Image   string   `json:"image" yaml:"image"`
	Command []string `json:"command" yaml:"command"`
	Args    []string `json:"args" yaml:"args"`
	Env     []envVar `json:"env" yaml:"env"`
	EnvFrom []envSrc `json:"envFrom" yaml:"envFrom"`
}

// envVar is an environment entry as far as the slot decides it: the
// value, or where it comes from (the API server fills in defaults such as
// a fieldRef's apiVersion, which aren't compared).
type envVar struct {
	Name      string `json:"name" yaml:"name"`
	Value     string `json:"value" yaml:"value"`
	ValueFrom *struct {
		FieldRef *struct {
			FieldPath string `json:"fieldPath" yaml:"fieldPath"`
		} `json:"fieldRef" yaml:"fieldRef"`
		ConfigMapKeyRef *keyRef `json:"configMapKeyRef" yaml:"configMapKeyRef"`
		SecretKeyRef    *keyRef `json:"secretKeyRef" yaml:"secretKeyRef"`
	} `json:"valueFrom" yaml:"valueFrom"`
}

type keyRef struct {
	Name string `json:"name" yaml:"name"`
	Key  string `json:"key" yaml:"key"`
}

type envSrc struct {
	Prefix       string `json:"prefix" yaml:"prefix"`
	ConfigMapRef *struct {
		Name string `json:"name" yaml:"name"`
	} `json:"configMapRef" yaml:"configMapRef"`
	SecretRef *struct {
		Name string `json:"name" yaml:"name"`
	} `json:"secretRef" yaml:"secretRef"`
}

type podSpec struct {
	InitContainers []container `json:"initContainers" yaml:"initContainers"`
	Containers     []container `json:"containers" yaml:"containers"`
}

// podTemplate is what a workload's pods are made from, as far as the
// slot sets it: the template's annotations (where a chart puts its
// config checksums) and the containers.
type podTemplate struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations" yaml:"annotations"`
	} `json:"metadata" yaml:"metadata"`
	Spec podSpec `json:"spec" yaml:"spec"`
}

// containers are a pod spec's containers by name.
func (s podSpec) containers() map[string]container {
	out := map[string]container{}
	for _, c := range append(append([]container(nil), s.InitContainers...), s.Containers...) {
		out[c.Name] = c
	}
	return out
}

// sameTemplate is whether the live template is the slot's: every
// annotation the slot sets has its value (others, such as a restart
// stamp, may be added), and every container the slot names runs its
// image, command, arguments and environment.
func sameTemplate(want, got podTemplate) bool {
	for k, v := range want.Metadata.Annotations {
		if got.Metadata.Annotations[k] != v {
			return false
		}
	}
	live := got.Spec.containers()
	for name, w := range want.Spec.containers() {
		g, ok := live[name]
		if !ok || g.Image != w.Image || !slices.Equal(g.Command, w.Command) || !slices.Equal(g.Args, w.Args) ||
			!slices.EqualFunc(g.Env, w.Env, sameEnv) || !slices.EqualFunc(g.EnvFrom, w.EnvFrom, sameEnvFrom) {
			return false
		}
	}
	return true
}

func sameEnv(a, b envVar) bool {
	if a.Name != b.Name || a.Value != b.Value || (a.ValueFrom == nil) != (b.ValueFrom == nil) {
		return false
	}
	if a.ValueFrom == nil {
		return true
	}
	x, y := a.ValueFrom, b.ValueFrom
	return fieldPath(x.FieldRef) == fieldPath(y.FieldRef) && sameRef(x.ConfigMapKeyRef, y.ConfigMapKeyRef) && sameRef(x.SecretKeyRef, y.SecretKeyRef)
}

func fieldPath(f *struct {
	FieldPath string `json:"fieldPath" yaml:"fieldPath"`
}) string {
	if f == nil {
		return ""
	}
	return f.FieldPath
}

func sameRef(a, b *keyRef) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func sameEnvFrom(a, b envSrc) bool {
	name := func(r *struct {
		Name string `json:"name" yaml:"name"`
	}) string {
		if r == nil {
			return ""
		}
		return r.Name
	}
	return a.Prefix == b.Prefix && name(a.ConfigMapRef) == name(b.ConfigMapRef) && name(a.SecretRef) == name(b.SecretRef)
}

type workload struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Namespace  string            `json:"namespace"`
		Name       string            `json:"name"`
		Generation int64             `json:"generation"`
		Labels     map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int64      `json:"replicas"`
		Template podTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64  `json:"observedGeneration"`
		Replicas           int64  `json:"replicas"`
		UpdatedReplicas    int64  `json:"updatedReplicas"`
		AvailableReplicas  int64  `json:"availableReplicas"`
		ReadyReplicas      int64  `json:"readyReplicas"`
		CurrentRevision    string `json:"currentRevision"`
		UpdateRevision     string `json:"updateRevision"`
		// DaemonSets count by nodes.
		DesiredNumberScheduled int64 `json:"desiredNumberScheduled"`
		UpdatedNumberScheduled int64 `json:"updatedNumberScheduled"`
		NumberAvailable        int64 `json:"numberAvailable"`
	} `json:"status"`
}

type workloadList struct {
	Items []workload `json:"items"`
}

// workloadKinds are the kinds that roll out.
var workloadKinds = []string{"Deployment", "StatefulSet", "DaemonSet"}

// wanted is a workload in the slot's stacks, with the pod template its
// pods are made from at the slot's version.
type wanted struct {
	kind, ns, name string
	template       podTemplate
	// replicas is what the slot's stack sets (1 when it sets none).
	replicas int64
}

func (w wanted) key() string { return w.kind + " " + w.ns + "/" + w.name }

// onStacks are the slot's stacks k0s applies: those whose switch, if any,
// is on.
func (p *Probe) onStacks() ([]string, error) {
	dirs, err := os.ReadDir(filepath.Join(p.Slot, "manifests"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	off := productswitch.OffStacks(p.Slot, p.SwitchDir)
	var on []string
	for _, d := range dirs {
		if d.IsDir() && !slices.Contains(off, d.Name()) {
			on = append(on, d.Name())
		}
	}
	return on, nil
}

// wantedWorkloads are the Deployments, StatefulSets and DaemonSets the
// slot's stacks hold, read from their files with the box's own values put
// in, as k0s-interim and productswitch hand them to k0s.
func (p *Probe) wantedWorkloads(stacks []string) ([]wanted, error) {
	kernel, _ := os.Hostname()
	values := boxvalues.Table(p.Slot, boxvalues.Read(p.SwitchDir), kernel)
	var out []wanted
	for _, st := range stacks {
		files, err := filepath.Glob(filepath.Join(p.Slot, "manifests", st, "*.y*ml"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			ws, err := readWorkloads(f, values)
			if err != nil {
				return nil, fmt.Errorf("the stack %s doesn't read: %w", st, err)
			}
			out = append(out, ws...)
		}
	}
	return out, nil
}

func readWorkloads(file string, values []boxvalues.Pair) ([]wanted, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- a stack of the installed slot
	if err != nil {
		return nil, err
	}
	b = boxvalues.Substitute(b, values)
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []wanted
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Namespace string `yaml:"namespace"`
				Name      string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				Replicas *int64      `yaml:"replicas"`
				Template podTemplate `yaml:"template"`
			} `yaml:"spec"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(file), err)
		}
		if !slices.Contains(workloadKinds, doc.Kind) {
			continue
		}
		ns := doc.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		replicas := int64(1)
		if doc.Spec.Replicas != nil {
			replicas = *doc.Spec.Replicas
		}
		out = append(out, wanted{kind: doc.Kind, ns: ns, name: doc.Metadata.Name, template: doc.Spec.Template, replicas: replicas})
	}
}

// rollout says what the stacks' workloads wait for, "Rolling out (n of m
// ready): waiting for <namespace>/<name>, <why>", or "" once every one has
// rolled out. A workload of the slot's stacks must be there and its pod
// template must be the slot's (k0s has applied the new version: images,
// commands, arguments, environment and template annotations, so a change
// that keeps the image counts too); then it,
// like every workload k0s labels with a stack, must have rolled out: its
// controller has seen the latest spec, and every replica is updated and
// available (the old ones gone).
func (p *Probe) rollout(ctx context.Context, stacks []string) (string, error) {
	want, err := p.wantedWorkloads(stacks)
	if err != nil {
		return "", err
	}
	live, err := p.liveWorkloads(ctx)
	if err != nil {
		return "", err
	}
	return rolloutWith(want, live, func(workload) bool { return true }), nil
}

// rolloutWith is rollout's answer for want against the live workloads:
// each of want must be there at the slot's template and rolled out, and so
// must every other live workload include admits.
func rolloutWith(want []wanted, items []workload, include func(workload) bool) string {
	live := map[string]workload{}
	for _, w := range items {
		live[w.Kind+" "+w.Metadata.Namespace+"/"+w.Metadata.Name] = w
	}
	var waiting []string
	seen := map[string]bool{}
	total := 0
	for _, w := range want {
		if seen[w.key()] {
			continue
		}
		seen[w.key()] = true
		total++
		name := w.ns + "/" + w.name
		got, ok := live[w.key()]
		switch {
		case !ok:
			waiting = append(waiting, name+", not created yet")
		case !sameTemplate(w.template, got.Spec.Template):
			waiting = append(waiting, name+", the new version isn't applied yet")
		default:
			if why := rolledOut(got); why != "" {
				waiting = append(waiting, name+", "+why)
			}
		}
	}
	for _, w := range items {
		key := w.Kind + " " + w.Metadata.Namespace + "/" + w.Metadata.Name
		if seen[key] || !include(w) {
			continue
		}
		seen[key] = true
		total++
		if why := rolledOut(w); why != "" {
			waiting = append(waiting, w.Metadata.Namespace+"/"+w.Metadata.Name+", "+why)
		}
	}
	if len(waiting) == 0 {
		return ""
	}
	return fmt.Sprintf("Rolling out (%d of %d ready): waiting for %s", total-len(waiting), total, waiting[0])
}

// rolledOut says why w hasn't rolled out yet, or "".
func rolledOut(w workload) string {
	st := w.Status
	if st.ObservedGeneration < w.Metadata.Generation {
		return "the new version isn't picked up yet"
	}
	if w.Kind == "DaemonSet" {
		if st.UpdatedNumberScheduled < st.DesiredNumberScheduled || st.NumberAvailable < st.DesiredNumberScheduled {
			return fmt.Sprintf("%d of %d updated", st.UpdatedNumberScheduled, st.DesiredNumberScheduled)
		}
		return ""
	}
	want := int64(1)
	if w.Spec.Replicas != nil {
		want = *w.Spec.Replicas
	}
	if st.UpdatedReplicas < want || st.Replicas > want || st.AvailableReplicas < want && st.ReadyReplicas < want {
		return fmt.Sprintf("%d of %d updated, %d running", st.UpdatedReplicas, want, st.Replicas)
	}
	if w.Kind == "StatefulSet" && st.UpdateRevision != "" && st.CurrentRevision != st.UpdateRevision {
		return "the new revision isn't current yet"
	}
	return ""
}

// images counts the bundle's images that containerd has: each archive is
// <hex of the pinned digest>.tar, and an imported image lists that digest.
func (p *Probe) images(ctx context.Context) (have, want int, err error) {
	tars, err := filepath.Glob(filepath.Join(p.Slot, "images", "*.tar"))
	if err != nil {
		return 0, 0, err
	}
	out, err := p.run(ctx, "ctr", "--address", p.Containerd, "--namespace", "k8s.io", "images", "list")
	if err != nil {
		return 0, len(tars), nil
	}
	listed := string(out)
	for _, t := range tars {
		if strings.Contains(listed, "sha256:"+strings.TrimSuffix(filepath.Base(t), ".tar")) {
			have++
		}
	}
	return have, len(tars), nil
}

// stacks are the stacks k0s hasn't applied anything of yet.
func (p *Probe) stacks(ctx context.Context, on []string) ([]string, error) {
	var missing []string
	for _, st := range on {
		out, err := p.kubectl(ctx, "get", "namespaces,deployments,daemonsets,statefulsets,services,configmaps,serviceaccounts,roles,rolebindings", "--all-namespaces", "-l", StackLabel+"="+st, "-o", "name")
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			missing = append(missing, st)
		}
	}
	return missing, nil
}

type podList struct {
	Items []podItem `json:"items"`
}

type containerStatus struct {
	Name  string `json:"name"`
	State struct {
		Waiting *struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"waiting"`
	} `json:"state"`
	LastState struct {
		Terminated *struct {
			Reason   string `json:"reason"`
			Message  string `json:"message"`
			ExitCode int    `json:"exitCode"`
		} `json:"terminated"`
	} `json:"lastState"`
	RestartCount int `json:"restartCount"`
}

type podItem struct {
	Metadata struct {
		Namespace         string            `json:"namespace"`
		Name              string            `json:"name"`
		DeletionTimestamp *string           `json:"deletionTimestamp"`
		Labels            map[string]string `json:"labels"`
	} `json:"metadata"`
	Status struct {
		Phase      string `json:"phase"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
	} `json:"status"`
}

// pods counts the pods that should run and how many of them are ready,
// and the old ones still stopping (Terminating); why names the first pod
// that isn't ready and why its container waits (CrashLoopBackOff, say). A
// finished pod (a Job's) or one that failed for good (evicted) counts as
// none of them: its controller has replaced it.
func (p *Probe) pods(ctx context.Context) (ready, total, stopping int, why string, err error) {
	items, err := p.podItems(ctx)
	if err != nil {
		return 0, 0, 0, "", err
	}
	ready, total, stopping, why, _ = countPods(items, func(podItem) bool { return true })
	return ready, total, stopping, why, nil
}

// countPods is pods for the pods include admits; never is whether the pod
// why names waits for a reason no retry clears (neverStarts), and then why
// carries the container's message too.
func countPods(items []podItem, include func(podItem) bool) (ready, total, stopping int, why string, never bool) {
	for _, it := range items {
		if !include(it) || it.Status.Phase == "Succeeded" || it.Status.Phase == "Failed" {
			continue
		}
		if it.Metadata.DeletionTimestamp != nil {
			stopping++
			continue
		}
		total++
		isReady := false
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				isReady = true
			}
		}
		if isReady {
			ready++
			continue
		}
		if why != "" {
			continue
		}
		for _, cs := range append(append([]containerStatus(nil), it.Status.InitContainerStatuses...), it.Status.ContainerStatuses...) {
			if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "PodInitializing" {
				why = it.Metadata.Namespace + "/" + it.Metadata.Name + " " + w.Reason
				if neverStarts[w.Reason] {
					never = true
					if w.Message != "" {
						why += ": " + w.Message
					}
				} else if t := cs.LastState.Terminated; t != nil && t.Message != "" {
					why += ": " + t.Message
				}
				break
			}
		}
	}
	return ready, total, stopping, why, never
}

// edgeAnswers is whether 443 answers with something other than edgefall's
// page or an edge error: the product, or the edge's own answer for a path
// it has no route for.
func (p *Probe) edgeAnswers(ctx context.Context) bool {
	c := p.HTTP
	if c == nil {
		c = &http.Client{
			Timeout: askTimeout,
			// #nosec G402 -- loopback, the box's own edge: only who answers matters, not the certificate
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+p.Edge+"/", nil)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.Header.Get(StateHeader) == "" && (resp.StatusCode < 502 || resp.StatusCode > 504)
}
