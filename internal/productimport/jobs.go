// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productimport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"gopkg.in/yaml.v3"
)

// JobReader reads a step's Job and its pods from the cluster as kubectl
// get -o json prints them: the Job (empty when there is none yet) and the
// List of the pods labelled with its name.
type JobReader func(ctx context.Context, namespace, job string) (jobJSON, podsJSON []byte, err error)

// ending is how a step ended that didn't write its exit code, as the
// box read it from the step's Job; it's kept next to the step's output.
type ending struct {
	Exit   int       `json:"exit"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// ended marks r done from the box's record of its end, or else from its
// Job, when the Job or its pod says it ended.
func (m *Manager) ended(r *Run, base string) {
	if b, err := os.ReadFile(base + endedSuffix); err == nil { // #nosec G304 -- the box's own file
		var e ending
		if json.Unmarshal(b, &e) == nil {
			r.Done, r.Exit, r.Reason, r.Finished = true, e.Exit, e.Reason, e.At
			return
		}
	}
	if m.Jobs == nil {
		return
	}
	var j stepJob
	raw, err := os.ReadFile(filepath.Join(m.Stack, "job-"+r.Job+".yaml")) // #nosec G304 -- the box's own stack
	if err != nil || yaml.Unmarshal(raw, &j) != nil {
		return
	}
	ns := j.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	ctx, cancel := context.WithTimeout(context.Background(), jobReadTimeout)
	defer cancel()
	jobJSON, podsJSON, err := m.Jobs(ctx, ns, r.Job)
	if err != nil {
		m.lg().Warn("productimport: the step's Job can't be read; it shows running", log.F("job", r.Job), log.F("error", err.Error()))
		return
	}
	e, ok := jobEnding(r.Step, jobJSON, podsJSON)
	if !ok {
		m.lg().Debug("productimport: the step's Job still runs", log.F("job", r.Job))
		return
	}
	// The step may have written its exit code between the first look and
	// the Job's read: its own wins.
	if b, err := os.ReadFile(base + ".txt.exit"); err == nil { // #nosec G304 -- the box's own file
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			r.Done, r.Exit = true, n
			return
		}
	}
	if e.At.IsZero() {
		e.At = m.now().UTC()
	}
	r.Done, r.Exit, r.Reason, r.Finished = true, e.Exit, e.Reason, e.At.UTC()
	m.lg().Warn("productimport: a step ended without writing its exit code; its Job says why", log.F("job", r.Job), log.F("exit", e.Exit), log.F("reason", e.Reason))
	b, _ := json.Marshal(ending{Exit: r.Exit, Reason: r.Reason, At: r.Finished})
	if err := os.WriteFile(base+endedSuffix+".new", b, 0o600); err == nil { // #nosec G703 -- a checked job name in the box's own directory
		if err := os.Rename(base+endedSuffix+".new", base+endedSuffix); err != nil {
			m.lg().Warn("productimport: how the step ended can't be kept", log.F("job", r.Job), log.F("error", err.Error()))
		}
	}
}

type kubeJob struct {
	Status struct {
		Conditions []struct {
			Type, Status, Reason, Message string
			LastTransitionTime            time.Time `json:"lastTransitionTime"`
		} `json:"conditions"`
	} `json:"status"`
}

type kubePods struct {
	Items []struct {
		Spec struct {
			Containers []struct {
				Name      string `json:"name"`
				Resources struct {
					Limits map[string]string `json:"limits"`
				} `json:"resources"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			Phase, Reason, Message string
			ContainerStatuses      []struct {
				Name  string `json:"name"`
				State struct {
					Terminated *struct {
						ExitCode   int       `json:"exitCode"`
						Reason     string    `json:"reason"`
						FinishedAt time.Time `json:"finishedAt"`
					} `json:"terminated"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// oomExit is the exit code of a process the kernel killed (128 + SIGKILL).
const oomExit = 137

// jobEnding reads how a step's Job ended: a container that terminated
// (the Job's pods never restart), a pod that failed without one (evicted,
// say), or a Job marked Failed. A Job not there yet, or still running,
// hasn't ended.
func jobEnding(step Step, jobJSON, podsJSON []byte) (ending, bool) {
	if len(bytes.TrimSpace(jobJSON)) == 0 {
		return ending{}, false
	}
	var pods kubePods
	_ = json.Unmarshal(podsJSON, &pods)
	for _, p := range pods.Items {
		for _, c := range p.Status.ContainerStatuses {
			t := c.State.Terminated
			if t == nil {
				continue
			}
			e := ending{Exit: t.ExitCode, At: t.FinishedAt}
			switch {
			case t.Reason == "OOMKilled":
				if e.Exit == 0 {
					e.Exit = oomExit
				}
				limit := ""
				for _, s := range p.Spec.Containers {
					if s.Name == c.Name {
						limit = s.Resources.Limits["memory"]
					}
				}
				e.Reason = fmt.Sprintf("the %s step ran out of memory", step)
				if limit != "" {
					e.Reason += " (limit " + limit + ")"
				}
			case t.ExitCode == 0:
				e.Reason = fmt.Sprintf("the %s step ended without writing its result", step)
			default:
				e.Reason = fmt.Sprintf("the %s step ended with exit code %d (%s) before it wrote its result", step, t.ExitCode, t.Reason)
			}
			return e, true
		}
		if p.Status.Phase == "Failed" {
			what := "failed"
			if p.Status.Reason == "Evicted" {
				what = "was evicted"
			} else if p.Status.Reason != "" {
				what += " (" + p.Status.Reason + ")"
			}
			e := ending{Exit: 1, Reason: fmt.Sprintf("the %s step's pod %s", step, what)}
			if p.Status.Message != "" {
				e.Reason += " (" + p.Status.Message + ")"
			}
			return e, true
		}
	}
	var j kubeJob
	if json.Unmarshal(jobJSON, &j) != nil {
		return ending{}, false
	}
	for _, c := range j.Status.Conditions {
		if c.Type == "Failed" && c.Status == "True" {
			why := c.Reason
			if c.Message != "" {
				why += ": " + c.Message
			}
			return ending{Exit: 1, Reason: fmt.Sprintf("the %s step's Job failed (%s)", step, why), At: c.LastTransitionTime}, true
		}
	}
	return ending{}, false
}
