// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

// The always-on stacks are put in front of k0s all at once, and k0s's
// applier takes each as one pass. A stack that declares cert-manager's
// objects (an Issuer, the Certificates the services mount) is rejected for
// those when cert-manager's CRDs or webhook aren't ready yet, as they aren't
// on the first start after an update from a product that had no cert-manager;
// the stack's other objects go in, so it looks applied, and the applier runs
// the stack again only when its files change. Nothing then makes the
// Certificates, and a pod waits on its Secret until its phase times out.
// The cluster step checks them, puts the stack in front of k0s again, a
// bounded number of times, and says what it waits for.
const (
	// certRetryEvery spaces the box's putting a stack in front of k0s again.
	certRetryEvery = 20 * time.Second
	// certRetries is how many times it does that before the step fails.
	certRetries = 6
)

// certTry is the cluster step's record of putting a stack in front of k0s
// again for its cert-manager objects.
type certTry struct {
	n  int
	at time.Time
}

var certDocRE = regexp.MustCompile(`(?m)^apiVersion: cert-manager\.io/`)

// certDecl is a cert-manager object a stack's files declare.
type certDecl struct {
	kind, ns, name string
	doc            []byte
}

func (d certDecl) key() string { return d.kind + " " + d.ns + "/" + d.name }

func (p *Probe) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// declaredCerts are the cert-manager.io objects the slot's stack declares.  // scrub:allow=fqdn -- a Kubernetes API group
func (p *Probe) declaredCerts(stack string) ([]certDecl, error) {
	files, err := filepath.Glob(filepath.Join(p.Slot, "manifests", stack, "*.y*ml"))
	if err != nil {
		return nil, err
	}
	var out []certDecl
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- the installed slot's own stack
		if err != nil {
			return nil, err
		}
		if !certDocRE.Match(b) {
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		for {
			var d map[string]any
			if err := dec.Decode(&d); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("productup: %s doesn't parse: %w", f, err)
			}
			if av, _ := d["apiVersion"].(string); !strings.HasPrefix(av, "cert-manager.io/") { // scrub:allow=fqdn -- a Kubernetes API group
				continue
			}
			md, _ := d["metadata"].(map[string]any)
			doc, err := yaml.Marshal(d)
			if err != nil {
				return nil, err
			}
			out = append(out, certDecl{kind: fmt.Sprint(d["kind"]), ns: fmt.Sprint(md["namespace"]), name: fmt.Sprint(md["name"]), doc: doc})
		}
	}
	return out, nil
}

// certificates is whether every cert-manager object the stacks declare is in
// the cluster; when one isn't, the result says what the step waits for, and
// the stack is put in front of k0s again (at most certRetries times, a
// certRetryEvery apart), after which the step fails with the API server's own
// answer to the object.
func (p *Probe) certificates(ctx context.Context, stacks []string) (Result, bool, error) {
	for _, st := range stacks {
		want, err := p.declaredCerts(st)
		if err != nil {
			return Result{}, false, err
		}
		if len(want) == 0 {
			continue
		}
		out, err := p.kubectl(ctx, "get", "issuers.cert-manager.io,certificates.cert-manager.io", "--all-namespaces", "-l", StackLabel+"="+st, "-o", "json") // scrub:allow=fqdn -- a Kubernetes API group
		if err != nil {
			return Result{Step: StepCluster, Detail: "Waiting for cert-manager's CRDs, which " + st + " needs for its certificates"}, false, nil
		}
		var l struct {
			Items []struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Namespace string `json:"namespace"`
					Name      string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal(out, &l); err != nil {
			return Result{}, false, fmt.Errorf("productup: the cert-manager objects don't parse: %w", err)
		}
		have := map[string]bool{}
		for _, it := range l.Items {
			have[it.Kind+" "+it.Metadata.Namespace+"/"+it.Metadata.Name] = true
		}
		var missing []certDecl
		for _, d := range want {
			if !have[d.key()] {
				missing = append(missing, d)
			}
		}
		if len(missing) == 0 {
			p.certMu.Lock()
			delete(p.certTries, st)
			p.certMu.Unlock()
			continue
		}
		return p.certMissing(ctx, st, missing, len(want))
	}
	return Result{}, true, nil
}

func (p *Probe) certMissing(ctx context.Context, st string, missing []certDecl, total int) (Result, bool, error) {
	p.certMu.Lock()
	defer p.certMu.Unlock()
	if p.certTries == nil {
		p.certTries = map[string]certTry{}
	}
	t := p.certTries[st]
	now := p.now()
	waiting := Result{Step: StepCluster, Detail: fmt.Sprintf("Waiting for k0s to apply %s's certificates (%d of %d missing)", st, len(missing), total)}
	if !t.at.IsZero() && now.Sub(t.at) < certRetryEvery {
		return waiting, false, nil
	}
	if t.n >= certRetries {
		var names []string
		for _, d := range missing {
			names = append(names, d.kind+" "+d.ns+"/"+d.name)
		}
		return Result{Step: StepCluster, Failed: true, Detail: fmt.Sprintf("%s's %s were never applied, though the stack was put in front of k0s %d times: %s", st, strings.Join(names, ", "), t.n, p.certRejection(ctx, missing[0]))}, false, nil
	}
	if err := productswitch.RefreshStack(p.Slot, p.SwitchDir, p.Manifests, st); err != nil {
		return Result{}, false, err
	}
	p.certTries[st] = certTry{n: t.n + 1, at: now}
	return waiting, false, nil
}

// certRejection is what the API server answers to the object, for the
// failure message.
func (p *Probe) certRejection(ctx context.Context, d certDecl) string {
	f, err := os.CreateTemp("", "cert-*.yaml")
	if err != nil {
		return err.Error()
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(d.doc); err != nil {
		_ = f.Close()
		return err.Error()
	}
	if err := f.Close(); err != nil {
		return err.Error()
	}
	if _, err := p.kubectl(ctx, "apply", "--dry-run=server", "-f", f.Name()); err != nil {
		return strings.TrimSpace(err.Error())
	}
	return "the API server accepts it now, and k0s hasn't applied it"
}
