// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command boxtool runs the real internal/backupset from inside a kind node,
// as accessd does on a box, for test/backups/rehearsal.sh. --die-at SIGKILLs
// it as the restore reaches a step, as a power loss would.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/backupset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const kubeconfig = "/etc/kubernetes/admin.conf"

// noServices stands in for the phases after the database; the rehearsal runs
// the chart alone, and the QEMU leg runs the services.
type noServices struct{}

func (noServices) Stop(context.Context) error { return nil }

func main() {
	fs := flag.NewFlagSet("boxtool", flag.ExitOnError)
	slot := fs.String("slot", "/box/slot", "the slot holding product.yaml and the checks")
	root := fs.String("backup", "/box/backup", "the backup partition")
	data := fs.String("data", "/box/data", "the data root")
	dieAt := fs.String("die-at", "", "SIGKILL at this restore step")
	dieAfter := fs.Duration("die-after", 0, "how far into the step")
	hold := fs.Int64("hold", 0, "bytes of WAL the guard holds")
	stuck := fs.Duration("stuck", 0, "how long the archive stands still before the guard acts")
	ticks := fs.Int("ticks", 1, "the guard's looks")
	every := fs.Duration("every", time.Second, "between the guard's looks")
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "boxtool create|list|restore|settle|guard|remove [flags] [set]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	spec := func() (productspec.Spec, error) {
		s, err := productspec.Load(*slot)
		if err == nil && s.Backups != nil {
			s.Backups.Root = *root
		}
		return s, err
	}
	cluster := &backupset.Cluster{
		Tools: datamove.Exec{Prefix: func(c productspec.DataCluster) []string {
			return []string{"kubectl", "--kubeconfig", kubeconfig, "exec", "-i", "--namespace", c.Namespace, c.Name + "-0", "--container", c.ContainerOrDefault(), "--"}
		}},
		Kubectl: func(ctx context.Context, args ...string) ([]byte, error) {
			var out, errb bytes.Buffer
			c := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...) // #nosec G204 -- test-only, fixed tool
			c.Stdout, c.Stderr = &out, &errb
			if err := c.Run(); err != nil {
				return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
			}
			return out.Bytes(), nil
		},
	}
	note := func(action string, detail map[string]string) { fmt.Println("audit:", action, detail) }
	m := &backupset.Manager{Spec: spec, Engine: cluster, Audit: note}
	journal := filepath.Join(*data, backupset.JournalFile)
	r := &backupset.Restorer{Spec: spec, Engine: cluster, Kube: cluster, Slot: *slot, Journal: journal, DataRoot: *data, Audit: note}
	r.OnStep = func(step string) {
		if step == *dieAt {
			// A little into the step, so its work is under way.
			time.Sleep(*dieAfter)
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
	g := &backupset.Guard{Spec: spec, Engine: cluster, Restore: r, StateFile: filepath.Join(*data, "archive.json"), DataRoot: *data, HoldBytes: *hold, StuckAfter: *stuck, Audit: note}
	ctx := context.Background()
	var err error
	switch cmd {
	case "create":
		var mf backupset.Manifest
		if mf, err = m.Create(ctx, fs.Arg(0)); err == nil {
			fmt.Printf("set %s point %s base %s bytes %d\n", mf.Name, mf.Point, mf.Base, mf.Bytes)
		}
	case "list":
		var list []backupset.Set
		if list, err = m.List(); err == nil {
			for _, s := range list {
				fmt.Println(s.Name, s.Point, s.Bytes)
			}
		}
	case "remove":
		err = m.Remove(fs.Arg(0))
	case "restore":
		if err = r.Request(ctx, fs.Arg(0), "rehearsal"); err == nil {
			err = follow(r)
		}
	case "resume":
		err = follow(r)
	case "settle":
		err = r.Settle(ctx)
	case "guard":
		for i := range *ticks {
			if i > 0 {
				time.Sleep(*every)
			}
			g.Tick(ctx)
		}
		for _, w := range g.Warnings() {
			fmt.Println("warning:", w.Detail)
		}
	default:
		err = fmt.Errorf("no command %s", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "boxtool:", err)
		os.Exit(1)
	}
}

// follow asks as the phase loop does until the restore lets the product go.
func follow(r *backupset.Restorer) error {
	for {
		st := r.Ask(noServices{})
		j, err := r.Read()
		if err != nil {
			return err
		}
		if !st.Busy {
			fmt.Printf("restore: state %s why %q\n", j.State, j.Why)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}
