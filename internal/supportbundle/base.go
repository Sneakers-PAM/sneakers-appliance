// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Busybox runs every OS command: the root image has no other tools, and
// its applets run from the one binary. The fixed set's applets and options
// are held to build/busybox/busybox.config by a test.
const Busybox = "/bin/busybox"

// The tails of each form.
const (
	shortTail = 50
	fullTail  = 2000
)

// How long the slower sections may run.
const (
	clusterTimeout = 30 * time.Second
	logsTimeout    = 3 * time.Minute
	oneLogTimeout  = 10 * time.Second
)

// Exec runs argv with its output, both streams, going to w.
type Exec func(ctx context.Context, argv []string, w io.Writer) error

// Run is the real Exec. The child gets no input and only the environment
// it needs, and goes with the context; nothing runs through a shell.
func Run(ctx context.Context, argv []string, w io.Writer) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- the fixed set, or a section productspec checked
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "TERM=dumb"}
	cmd.Stdout, cmd.Stderr = w, w
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}

// Config says where a box's commands and files are.
type Config struct {
	// K0s is the installed k0s and Kubeconfig its admin kubeconfig.
	K0s, Kubeconfig string
	// State is the state volume, RunDir the runtime directory, Manifests
	// k0s's manifests directory and Progress the update progress file.
	State, RunDir, Manifests, Progress string
	// Exec runs a command; Run on the box.
	Exec Exec
	// Status writes the box's status, as `status` shows it.
	Status func(ctx context.Context, w io.Writer) error
	// Audit writes the newest n lines of the OS audit log.
	Audit func(ctx context.Context, w io.Writer, n int) error
}

func (c Config) busybox(words ...string) []string { return append([]string{Busybox}, words...) }

func (c Config) kubectl(words ...string) []string {
	return append([]string{c.K0s, "kubectl", "--kubeconfig", c.Kubeconfig}, words...)
}

func (c Config) run(argv []string) func(context.Context, io.Writer) error {
	return func(ctx context.Context, w io.Writer) error { return c.Exec(ctx, argv, w) }
}

// osCommand is a section of one busybox command, headed as typed.
func (c Config) osCommand(words ...string) Section {
	return Section{Command: strings.Join(words, " "), Run: c.run(c.busybox(words...))}
}

// kubeCommand is a section of one kubectl read.
func (c Config) kubeCommand(words ...string) Section {
	return Section{Command: "kubectl " + strings.Join(words, " "), Timeout: clusterTimeout, Run: c.run(c.kubectl(words...))}
}

// fileTail is the last n lines of a file; a log that isn't there yet is
// no failure.
func (c Config) fileTail(file, source string, n int, optional bool) Section {
	s := c.osCommand("tail", "-n", strconv.Itoa(n), file)
	s.Log, s.Optional = source, optional
	return s
}

func (c Config) fileCat(file string) Section {
	s := c.osCommand("cat", file)
	s.Optional = true
	return s
}

// Base is the base's fixed command set in form's order, the set Format
// versions: the OS, k0s, the cluster, the logs, the mounts and the update
// records. The commands only read, and each is bounded. The short form is
// the key sections with short tails; Full adds the rest.
func (c Config) Base(form Form) []Section {
	full := form == Full
	n := shortTail
	if full {
		n = fullTail
	}
	platform := filepath.Join(c.State, "platform")
	k0sLog := filepath.Join(c.State, "k0s", "prepare.log")
	console := filepath.Join(c.RunDir, "console.log")

	out := []Section{
		{Command: "status", Timeout: clusterTimeout, Run: c.Status},
		c.fileCat(filepath.Join(platform, "box-values")),
		c.osCommand("uname", "-a"),
		c.osCommand("uptime"),
		{Command: "k0s status", Timeout: clusterTimeout, Optional: true, Run: c.run([]string{c.K0s, "status"})},
		c.kubeCommand("get", "nodes", "-o", "wide"),
		c.kubeCommand("get", "all", "-A", "-o", "wide"),
	}
	events := c.kubeCommand("get", "events", "-A", "--sort-by=.lastTimestamp")
	if !full {
		events.Tail = shortTail
	}
	out = append(out, events)
	if full {
		out = append(out,
			c.kubeCommand("describe", "nodes"),
			c.kubeCommand("describe", "pods", "-A"),
		)
	}
	out = append(out, c.podLogs(n, !full, false), c.podLogs(n, !full, true))
	out = append(out, c.fileTail(console, "box", n, true))
	if full {
		out = append(out, c.fileTail(console+".1", "box", n, true))
	}
	out = append(out, c.fileTail(k0sLog, "k0s", n, true))
	if full {
		out = append(out, c.fileTail(k0sLog+".1", "k0s", n, true))
	}
	out = append(out,
		c.fileCat(c.Progress),
		Section{Command: fmt.Sprintf("os-audit tail -n %d", n), Log: "audit", Run: func(ctx context.Context, w io.Writer) error { return c.Audit(ctx, w, n) }},
		c.osCommand("mount"),
		c.osCommand("df", "-h"),
	)
	listing := c.osCommand("ls", "-laR", "--full-time", c.Manifests)
	listing.Optional = true
	if !full {
		listing.Tail = shortTail
	}
	out = append(out, listing,
		c.fileCat(filepath.Join(platform, "phase-placed")),
		c.fileCat(filepath.Join(platform, "switches")),
		c.osCommand("ps", "w"),
	)
	if full {
		out = append(out,
			c.osCommand("free"),
			c.osCommand("ip", "addr"),
			c.osCommand("ip", "route"),
			c.osCommand("dmesg"),
		)
	}
	return append(out, c.secretNames(), c.envNames())
}

// secretNames lists the Secrets as kubectl's plain table: the API server
// sends a table's rows with no data in them, so the values never leave it.
func (c Config) secretNames() Section { return c.kubeCommand("get", "secrets", "-A") }

// envNames lists every container's env var names and the Secrets and
// ConfigMaps it loads whole. It asks for names only, so a value never
// reaches the output.
func (c Config) envNames() Section {
	return c.kubeCommand("get", "pods", "-A", "-o",
		"custom-columns=NAMESPACE:.metadata.namespace,POD:.metadata.name,ENV:.spec.containers[*].env[*].name,ENV_FROM_SECRET:.spec.containers[*].envFrom[*].secretRef.name,ENV_FROM_CONFIGMAP:.spec.containers[*].envFrom[*].configMapRef.name")
}

// podColumns are what the pod listing asks: in the short form only the
// pods that need a look get their logs read.
const podColumns = "custom-columns=NS:.metadata.namespace,POD:.metadata.name,CONTAINERS:.spec.containers[*].name,RESTARTS:.status.containerStatuses[*].restartCount,READY:.status.containerStatuses[*].ready"

type container struct {
	namespace, pod, name string
	restarted, unready   bool
}

// parsePods reads the listing. containerStatuses is empty for a pod that
// hasn't started, and then its containers aren't ready.
func parsePods(out string) []container {
	var cs []container
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		restarts, ready := strings.Split(f[3], ","), strings.Split(f[4], ",")
		for i, name := range strings.Split(f[2], ",") {
			c := container{namespace: f[0], pod: f[1], name: name, unready: true}
			if i < len(restarts) {
				n, err := strconv.Atoi(restarts[i])
				c.restarted = err == nil && n > 0
			}
			if i < len(ready) {
				c.unready = ready[i] != "true"
			}
			cs = append(cs, c)
		}
	}
	return cs
}

// podLogs is every container's log, or with previous the log of the
// container before it for the ones that restarted. onlyTroubled is the
// short form: containers that aren't ready or have restarted. Each log
// has its own bound, so one stuck container costs the section ten seconds.
func (c Config) podLogs(tail int, onlyTroubled, previous bool) Section {
	heading := fmt.Sprintf("kubectl logs <every container> --timestamps --tail=%d", tail)
	if onlyTroubled {
		heading = fmt.Sprintf("kubectl logs <each container not ready or restarted> --timestamps --tail=%d", tail)
	}
	if previous {
		heading = fmt.Sprintf("kubectl logs <each restarted container> --previous --timestamps --tail=%d", tail)
	}
	return Section{Command: heading, Log: "pods", Timeout: logsTimeout, Run: func(ctx context.Context, w io.Writer) error {
		var list bytes.Buffer
		lctx, cancel := context.WithTimeout(ctx, clusterTimeout)
		defer cancel()
		if err := c.Exec(lctx, c.kubectl("get", "pods", "-A", "--no-headers", "-o", podColumns), &list); err != nil {
			return fmt.Errorf("the pods can't be listed: %w", err)
		}
		for _, p := range parsePods(list.String()) {
			if previous && !p.restarted || onlyTroubled && !p.restarted && !p.unready {
				continue
			}
			if _, err := fmt.Fprintf(w, "--- %s/%s/%s\n", p.namespace, p.pod, p.name); err != nil {
				return err
			}
			args := []string{"logs", "-n", p.namespace, p.pod, "-c", p.name, "--prefix", "--timestamps", "--tail=" + strconv.Itoa(tail)}
			if previous {
				args = append(args, "--previous")
			}
			one, done := context.WithTimeout(ctx, oneLogTimeout)
			err := c.Exec(one, c.kubectl(args...), w)
			done()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if _, werr := fmt.Fprintf(w, "(no log: %v)\n", err); werr != nil {
					return werr
				}
			}
		}
		return nil
	}}
}

// Product is the sections spec declares for form, each run as productspec
// checked it. A kubectl log is a log, so it joins the timeline.
func (c Config) Product(spec productspec.Spec, form Form) []Section {
	var out []Section
	tail := fullTail
	if form == Short {
		tail = shortTail
	}
	for _, p := range spec.Support {
		if form == Short && !p.Short {
			continue
		}
		s := Section{Command: p.Title, Product: true, Timeout: p.Deadline()}
		for _, r := range p.Redact {
			s.Redact = append(s.Redact, regexp.MustCompile(r))
		}
		if k := p.Kubectl; k != nil {
			s.Run = c.run(c.kubectl(k.Args(tail)...))
			if k.Verb == "logs" {
				s.Log = "product"
			}
		} else {
			s.Run = c.run(c.busybox(p.Words()...))
		}
		out = append(out, s)
	}
	return out
}
