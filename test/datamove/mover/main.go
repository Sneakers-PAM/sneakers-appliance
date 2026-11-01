// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command mover runs the box's data move, the real internal/datamove, against
// a kind cluster for test/datamove/rehearsal.sh: kubectl exec stands in for
// `k0s kubectl exec`, and scaling the Deployments for stopping a phase. With
// -die-at it SIGKILLs itself at that point of the move, as a power loss would.
// The cert command writes the Secret a box issues, by the box's own code.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mover:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("mover move|cert")
	}
	switch args[0] {
	case "move":
		return move(args[1:])
	case "cert":
		return cert(args[1:])
	}
	return fmt.Errorf("no command %q", args[0])
}

// cert prints the named box certificate's Secret, issued by boxsecrets from
// the slot's product.yaml, for kubectl apply.
func cert(args []string) error {
	fl := flag.NewFlagSet("cert", flag.ContinueOnError)
	slot := fl.String("slot", "", "the directory holding product.yaml")
	name := fl.String("secret", "", "the Secret's name")
	state := fl.String("state", "", "a scratch directory")
	if err := fl.Parse(args); err != nil {
		return err
	}
	st := &boxsecrets.Store{Dir: *state, Manifests: *state}
	if err := st.Ensure(*slot); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(*state, productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml")) // #nosec G304 -- the test's own scratch
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			return fmt.Errorf("no Secret %s: %w", *name, err)
		}
		md, _ := d["metadata"].(map[string]any)
		if d["kind"] == "Secret" && md["name"] == *name {
			out, err := yaml.Marshal(d)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(out)
			return err
		}
	}
}

func move(args []string) error {
	fl := flag.NewFlagSet("move", flag.ContinueOnError)
	slot := fl.String("slot", "", "the directory holding product.yaml and the checks")
	dir := fl.String("dir", "", "stands in for the backup partition and the state volume")
	dieAt := fl.String("die-at", "", "SIGKILL this process mid-dump, mid-restore or before-switch")
	stop := fl.String("stop", "", "the Deployments to scale to 0, comma-separated")
	settle := fl.Bool("settle", false, "record the box healthy, as the phase loop does")
	if err := fl.Parse(args); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(*slot, productspec.File)) // #nosec G304 -- the test's own slot
	if err != nil {
		return err
	}
	spec, err := productspec.Parse(b)
	if err != nil {
		return err
	}
	if spec.DataMove == nil {
		return errors.New("the product declares no data move")
	}
	var engine datamove.Engine = &datamove.PG{Shell: datamove.Exec{Prefix: kubectl}}
	if *dieAt != "" {
		engine = dying{Engine: engine, at: *dieAt}
	}
	m := &datamove.Move{
		Spec:      *spec.DataMove,
		Slot:      *slot,
		BackupDir: filepath.Join(*dir, "backup"),
		Journal:   filepath.Join(*dir, datamove.JournalFile),
		Volumes:   *dir,
		Engine:    engine,
		Services:  deployments{ns: spec.DataMove.Target.Namespace, names: strings.Split(*stop, ",")},
		// The room check has unit tests; a laptop's disk says nothing of a box's.
		Disk:     func(string) (datamove.Usage, error) { return datamove.Usage{Avail: 1 << 50, Device: 1}, nil },
		Progress: func(s string) { fmt.Println("move:", s) },
	}
	if *settle {
		return m.Settle()
	}
	start := time.Now()
	if err := m.Run(context.Background()); err != nil {
		return err
	}
	fmt.Printf("move: through in %.1f s\n", time.Since(start).Seconds())
	return nil
}

// kubectl runs the tools in the cluster's first pod.
func kubectl(c productspec.DataCluster) []string {
	return []string{"kubectl", "exec", "-i", "--namespace", c.Namespace, c.Name + "-0", "--container", c.ContainerOrDefault(), "--"}
}

type deployments struct {
	ns    string
	names []string
}

func (d deployments) Stop(ctx context.Context) error {
	if len(d.names) == 1 && d.names[0] == "" {
		return errors.New("a move with data has to name what to stop")
	}
	for _, n := range d.names {
		cmd := exec.CommandContext(ctx, "kubectl", "--namespace", d.ns, "scale", "deployment/"+n, "--replicas=0") // #nosec G204 -- the test's own names
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("scaling %s: %w: %s", n, err, out)
		}
	}
	for _, n := range d.names {
		for {
			out, err := exec.CommandContext(ctx, "kubectl", "--namespace", d.ns, "get", "deployment/"+n, "-o", "jsonpath={.status.replicas}").Output() // #nosec G204 -- as above
			if err != nil {
				return fmt.Errorf("reading %s: %w", n, err)
			}
			if s := strings.TrimSpace(string(out)); s == "" || s == "0" {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return nil
}

func (deployments) Start(context.Context) error { return nil }

// dying is the box's engine, up to the point a power loss takes it.
type dying struct {
	datamove.Engine
	at    string
	dumps int
}

func die() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL); select {} }

// halfway passes bytes on until half of limit has gone, then dies.
type halfway struct {
	w     io.Writer
	limit int
}

func (h *halfway) Write(p []byte) (int, error) {
	n, err := h.w.Write(p)
	if h.limit -= n; h.limit <= 0 {
		die()
	}
	return n, err
}

type halfRead struct {
	r     io.Reader
	limit int
}

func (h *halfRead) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if h.limit -= n; h.limit <= 0 {
		die()
	}
	return n, err
}

const dieAfter = 1 << 20

func (d dying) DumpDatabase(ctx context.Context, c productspec.DataCluster, db string, w io.Writer) error {
	if d.at == "mid-dump" && db == "sneakers_audit" {
		w = &halfway{w: w, limit: dieAfter}
	}
	return d.Engine.DumpDatabase(ctx, c, db, w)
}

func (d dying) RestoreDatabase(ctx context.Context, c productspec.DataCluster, db string, r io.Reader) error {
	if d.at == "mid-restore" && db == "sneakers_audit" {
		r = &halfRead{r: r, limit: dieAfter}
	}
	return d.Engine.RestoreDatabase(ctx, c, db, r)
}

func (d dying) Check(ctx context.Context, c productspec.DataCluster, db string, query []byte) (string, error) {
	out, err := d.Engine.Check(ctx, c, db, query)
	if d.at == "before-switch" {
		die()
	}
	return out, err
}
