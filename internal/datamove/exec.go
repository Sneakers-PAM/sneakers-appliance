// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// killGrace is how long a killed command may hold its output.
const killGrace = 5 * time.Second

// errorBytes is how much of a tool's error reaches an error or a log.
const errorBytes = 400

// Exec runs the tools by a command line in front of them: `k0s kubectl
// exec` on the box. The connection's settings go in as environment
// variables. No password does: the tool reads it from the pod's own
// environment, so it's never on a command line or in the box's memory.
type Exec struct {
	// Prefix is the command that runs what follows it in c's pod.
	Prefix func(c productspec.DataCluster) []string
	Logger log.Logger
}

// KubePrefix runs the tools in the cluster's first pod with the slot's k0s.
func KubePrefix(k0s, kubeconfig string) func(productspec.DataCluster) []string {
	return func(c productspec.DataCluster) []string {
		return []string{k0s, "kubectl", "--kubeconfig", kubeconfig, "exec", "-i", "--namespace", c.Namespace, c.Name + "-0", "--container", c.ContainerOrDefault(), "--"}
	}
}

// Argv is the command line of argv in c's pod.
func (e Exec) Argv(c productspec.DataCluster, argv []string) []string {
	script := `exec "$@"`
	if c.PasswordEnv != "" {
		script = `PGPASSWORD="$` + c.PasswordEnv + `" exec "$@"`
	}
	out := append([]string{}, e.Prefix(c)...)
	out = append(out, "sh", "-c", script, "sh", "env",
		"PGHOST="+c.Host, "PGPORT="+strconv.Itoa(c.PortOrDefault()),
		"PGUSER="+c.User, "PGSSLMODE="+c.SSLModeOrDefault())
	if c.SSLRootCert != "" {
		out = append(out, "PGSSLROOTCERT="+c.SSLRootCert)
	}
	return append(out, argv...)
}

// Run implements Shell. A cancelled context kills the command with every
// process it started.
func (e Exec) Run(ctx context.Context, c productspec.DataCluster, argv []string, in io.Reader, out io.Writer) error {
	full := e.Argv(c, argv)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...) // #nosec G204 -- the box's own tools, with arguments checked by productspec
	var stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = killGrace
	start := time.Now()
	err := cmd.Run()
	if e.Logger != nil {
		e.Logger.Debug("datamove: tool ended", log.F("tool", argv[0]), log.F("cluster", c.Name), log.F("seconds", int(time.Since(start).Seconds())), log.F("ok", err == nil))
	}
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s: %w", argv[0], ctx.Err())
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 127 {
			return fmt.Errorf("%s: %w", argv[0], ErrNoTool)
		}
		return fmt.Errorf("%s: %w: %s", argv[0], err, Scrub(stderr.String()))
	}
	return nil
}

// A tool's error can quote the row or statement it failed on, and a row
// can hold anything. These lines, and whatever follows the first of them,
// never leave the box's memory.
var quoting = regexp.MustCompile(`(?i)(^|\s)(DETAIL|CONTEXT|LINE \d+|QUERY|HINT|STATEMENT|Command was):`)

// Scrub keeps the part of a tool's error that says what went wrong and
// none that quotes the data: the first line that reads as an error, cut
// before anything that quotes, and bounded.
func Scrub(stderr string) string {
	var first string
	for line := range strings.Lines(stderr) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if first == "" {
			first = line
		}
		if strings.Contains(line, "error:") || strings.Contains(line, "ERROR:") || strings.Contains(line, "FATAL:") {
			first = line
			break
		}
	}
	if loc := quoting.FindStringIndex(first); loc != nil {
		first = first[:loc[0]]
	}
	if len(first) > errorBytes {
		first = first[:errorBytes]
	}
	return first
}
