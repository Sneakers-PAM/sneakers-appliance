// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productup tells how far the installed product has come up after
// a product apply or revert restarted k0s: k0s's API answers, the bundle's
// images are imported, its stacks are applied, the pods are ready and the
// edge answers 443 with the product, not the box-state page. accessd's
// osadmin backend (root) asks it every few seconds and shows the answer as
// the update's steps (docs/upgrades.md).
package productup

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

// The steps, in the order the product comes up, as UpgradeStep.id names
// them.
const (
	StepK0s       = "k0s"
	StepImages    = "images"
	StepManifests = "manifests"
	StepPods      = "pods"
	StepEdge      = "edge"
)

// Steps are every step, in order.
var Steps = []string{StepK0s, StepImages, StepManifests, StepPods, StepEdge}

// Result is the first step that isn't done, with what it waits for; Step
// is empty once the product answers on 443.
type Result struct {
	Step   string
	Detail string
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
	// applied, so it isn't waited for.
	SwitchDir string
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
// answering while they drain, so every stack's workloads must have rolled
// out and no old pod may still be stopping before it counts.
func (p *Probe) Check(ctx context.Context) (Result, error) {
	if _, err := p.kubectl(ctx, "get", "--raw", "/readyz"); err != nil {
		return Result{Step: StepK0s, Detail: "The Kubernetes API doesn't answer yet."}, nil
	}
	if have, want, err := p.images(ctx); err != nil {
		return Result{}, err
	} else if have < want {
		return Result{Step: StepImages, Detail: fmt.Sprintf("%d of %d images imported", have, want)}, nil
	}
	if missing, err := p.stacks(ctx); err != nil {
		return Result{}, err
	} else if len(missing) > 0 {
		return Result{Step: StepManifests, Detail: "Waiting for " + strings.Join(missing, ", ")}, nil
	}
	if waiting, err := p.rollout(ctx); err != nil {
		return Result{}, err
	} else if waiting != "" {
		return Result{Step: StepPods, Detail: waiting}, nil
	}
	ready, total, stopping, err := p.pods(ctx)
	if err != nil {
		return Result{}, err
	}
	if total == 0 || ready < total {
		return Result{Step: StepPods, Detail: fmt.Sprintf("%d of %d pods ready", ready, total)}, nil
	}
	if stopping > 0 {
		return Result{Step: StepPods, Detail: fmt.Sprintf("%d old %s still stopping", stopping, plural(stopping, "pod", "pods"))}, nil
	}
	if p.edgeAnswers(ctx) {
		return Result{}, nil
	}
	return Result{Step: StepEdge, Detail: "443 doesn't answer with the product yet."}, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

type workloadList struct {
	Items []struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Namespace  string `json:"namespace"`
			Name       string `json:"name"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Replicas *int64 `json:"replicas"`
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
	} `json:"items"`
}

// rollout names the first of the stacks' workloads that hasn't rolled out
// yet: its controller hasn't seen the latest spec, or not every replica is
// updated and available (the old ones gone); empty when all have.
func (p *Probe) rollout(ctx context.Context) (string, error) {
	out, err := p.kubectl(ctx, "get", "deployments,statefulsets,daemonsets", "--all-namespaces", "-l", StackLabel, "-o", "json")
	if err != nil {
		return "", err
	}
	var l workloadList
	if err := json.Unmarshal(out, &l); err != nil {
		return "", fmt.Errorf("the workload list doesn't parse: %w", err)
	}
	for _, w := range l.Items {
		name := w.Metadata.Namespace + "/" + w.Metadata.Name
		st := w.Status
		if st.ObservedGeneration < w.Metadata.Generation {
			return "Rolling out " + name + ": the new version isn't picked up yet", nil
		}
		if w.Kind == "DaemonSet" {
			if st.UpdatedNumberScheduled < st.DesiredNumberScheduled || st.NumberAvailable < st.DesiredNumberScheduled {
				return fmt.Sprintf("Rolling out %s: %d of %d updated", name, st.UpdatedNumberScheduled, st.DesiredNumberScheduled), nil
			}
			continue
		}
		want := int64(1)
		if w.Spec.Replicas != nil {
			want = *w.Spec.Replicas
		}
		if st.UpdatedReplicas < want || st.Replicas > want || st.AvailableReplicas < want && st.ReadyReplicas < want {
			return fmt.Sprintf("Rolling out %s: %d of %d updated, %d running", name, st.UpdatedReplicas, want, st.Replicas), nil
		}
		if w.Kind == "StatefulSet" && st.UpdateRevision != "" && st.CurrentRevision != st.UpdateRevision {
			return "Rolling out " + name + ": the new revision isn't current yet", nil
		}
	}
	return "", nil
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

// stacks are the bundle's stacks k0s hasn't applied anything of yet.
func (p *Probe) stacks(ctx context.Context) ([]string, error) {
	dirs, err := os.ReadDir(filepath.Join(p.Slot, "manifests"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	off := productswitch.OffStacks(p.Slot, p.SwitchDir)
	var missing []string
	for _, d := range dirs {
		if !d.IsDir() || slices.Contains(off, d.Name()) {
			continue
		}
		out, err := p.kubectl(ctx, "get", "namespaces,deployments,daemonsets,statefulsets,services,configmaps", "--all-namespaces", "-l", StackLabel+"="+d.Name(), "-o", "name")
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			missing = append(missing, d.Name())
		}
	}
	return missing, nil
}

type podList struct {
	Items []struct {
		Metadata struct {
			DeletionTimestamp *string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Status struct {
			Phase      string `json:"phase"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

// pods counts the pods that should run and how many of them are ready,
// and the old ones still stopping (Terminating); a finished pod (a Job's)
// counts as none of them.
func (p *Probe) pods(ctx context.Context) (ready, total, stopping int, err error) {
	out, err := p.kubectl(ctx, "get", "pods", "--all-namespaces", "-o", "json")
	if err != nil {
		return 0, 0, 0, err
	}
	var l podList
	if err := json.Unmarshal(out, &l); err != nil {
		return 0, 0, 0, fmt.Errorf("the pod list doesn't parse: %w", err)
	}
	for _, it := range l.Items {
		if it.Status.Phase == "Succeeded" {
			continue
		}
		if it.Metadata.DeletionTimestamp != nil {
			stopping++
			continue
		}
		total++
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready++
			}
		}
	}
	return ready, total, stopping, nil
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
