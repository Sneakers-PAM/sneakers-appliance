// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command stack turns a product's rendered charts into the k0s stacks its
// product bundle carries (build/product/sneakers/render.sh). It takes two
// renders, the switch off and on, and writes the always-on stack and the
// switch's stack:
//
//   - every namespaced object goes in the product's namespace, which the
//     stack creates;
//   - every container runs the image release.yaml pins, by digest, and is
//     never pulled (the box is airgapped);
//   - a PersistentVolumeClaim goes, and the volume that used it (or a
//     StatefulSet's volume claim template) becomes a hostPath under the
//     data directory, owned by the pod's user;
//   - an Ingress loses its host and TLS: the box's edge serves every name
//     on 443 with the box's certificate;
//   - no Secret value is carried: a Secret the chart renders must be one
//     the product.yaml declares as a box secret (the box makes it) and is
//     dropped, and every Secret a workload reads must be a declared box
//     secret, key and all;
//   - the switch's stack holds what only the on render has, and a
//     ConfigMap with the settings the named ConfigMaps change when it's on
//     (the workloads load it, optional);
//   - with phases in product.yaml, every workload goes in its phase's own
//     stack (a switch's stays in the switch's stack, which its phase must
//     place), labelled with the phase and its place in the order, and a
//     workload no phase names is refused (phases.go).
//
// It prints every image the stacks run.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

type options struct {
	Release, ProductYAML, Off, On, Out string
	// Namespace is the product's namespace; Stack and SwitchStack the two
	// stacks' names.
	Namespace, Stack, SwitchStack string
	// SwitchConfigMap is the ConfigMap the switch's stack carries, with
	// the settings SwitchFrom's ConfigMaps change when it's on.
	SwitchConfigMap string
	// secretKeys are the box secret keys that hold a secret setting, and
	// boxMaps the ConfigMaps the box writes; render fills them from
	// product.yaml.
	secretKeys, boxMaps map[string]bool
	SwitchFrom          []string
	// Data is the directory the hostPath volumes go under.
	Data string
}

func main() {
	var o options
	var from string
	fl := flag.NewFlagSet("stack", flag.ContinueOnError)
	fl.StringVar(&o.Release, "release", "", "release.yaml, with every image pinned by digest")
	fl.StringVar(&o.ProductYAML, "product-yaml", "", "the product's product.yaml (its box secrets)")
	fl.StringVar(&o.Off, "off", "", "the render with the switch off")
	fl.StringVar(&o.On, "on", "", "the render with the switch on")
	fl.StringVar(&o.Out, "out", "", "the stacks directory: <stack>/<stack>.yaml for each")
	fl.StringVar(&o.Namespace, "namespace", "", "the product's namespace")
	fl.StringVar(&o.Stack, "stack", "", "the always-on stack's name")
	fl.StringVar(&o.SwitchStack, "switch-stack", "", "the switch's stack name")
	fl.StringVar(&o.SwitchConfigMap, "switch-configmap", "", "the ConfigMap the switch's stack carries")
	fl.StringVar(&from, "switch-from", "", "the ConfigMaps whose changed settings it holds, comma-separated")
	fl.StringVar(&o.Data, "data", "", "the directory the hostPath volumes go under")
	if err := fl.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	o.SwitchFrom = strings.Split(from, ",")
	if err := render(o, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "stack:", err)
		os.Exit(1)
	}
}

type doc = map[string]any

func render(o options, w io.Writer) error {
	relYAML, err := os.ReadFile(o.Release) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	rel, err := bundle.ParseRelease(relYAML)
	if err != nil {
		return err
	}
	pins, err := pinned(rel)
	if err != nil {
		return err
	}
	pb, err := os.ReadFile(o.ProductYAML) // #nosec G304 G703 -- as above
	if err != nil {
		return err
	}
	spec, err := productspec.Parse(pb)
	if err != nil {
		return err
	}
	box := map[string]map[string]bool{}
	for _, b := range spec.BoxSecrets {
		if b.Namespace() != o.Namespace {
			continue
		}
		box[b.SecretName()] = map[string]bool{}
		for _, k := range b.Keys {
			box[b.SecretName()][k.Key] = true
		}
	}
	o.secretKeys, o.boxMaps = map[string]bool{}, map[string]bool{}
	for _, b := range spec.BoxSecrets {
		for _, k := range b.Keys {
			if _, secret := productspec.IsSetting(k.Setting); secret {
				o.secretKeys[k.Key] = true
			}
		}
	}
	for _, b := range spec.BoxSettings {
		if b.Namespace() == o.Namespace {
			o.boxMaps[b.ConfigMapName()] = true
		}
	}
	images := map[string]bool{}
	offDocs, err := convert(o, o.Off, pins, box, images)
	if err != nil {
		return err
	}
	onDocs, err := convert(o, o.On, pins, box, images)
	if err != nil {
		return err
	}
	switchDocs, err := split(o, offDocs, onDocs, w)
	if err != nil {
		return err
	}
	offDocs, phased, err := phaseSplit(o, spec, offDocs, switchDocs)
	if err != nil {
		return err
	}
	ns := doc{"apiVersion": "v1", "kind": "Namespace", "metadata": doc{"name": o.Namespace, "labels": partOf(o)}}
	if err := write(filepath.Join(o.Out, o.Stack, o.Stack+".yaml"), append([]doc{ns}, offDocs...)); err != nil {
		return err
	}
	for _, p := range spec.Phases {
		if err := write(filepath.Join(o.Out, p.Stack, p.Stack+".yaml"), phased[p.Stack]); err != nil {
			return err
		}
	}
	if err := write(filepath.Join(o.Out, o.SwitchStack, o.SwitchStack+".yaml"), switchDocs); err != nil {
		return err
	}
	list := make([]string, 0, len(images))
	for im := range images {
		list = append(list, im)
	}
	sort.Strings(list)
	_, err = fmt.Fprintf(w, "stack: %s %d objects, %s %d objects, %d images\n%s\n", o.Stack, len(offDocs)+1, o.SwitchStack, len(switchDocs), len(list), strings.Join(list, "\n"))
	return err
}

// pinned maps every image release.yaml pins (services, third party,
// platform) to its digest.
func pinned(rel *bundle.Release) (map[string]string, error) {
	out := map[string]string{}
	for _, g := range []map[string]bundle.Image{rel.Spec.Services, rel.Spec.Jobs, rel.Spec.ThirdParty, rel.Spec.Platform} {
		for name, im := range g {
			if !strings.HasPrefix(im.Digest, "sha256:") || len(im.Digest) != 71 {
				return nil, fmt.Errorf("release.yaml pins %s at %q, not a digest", name, im.Digest)
			}
			out[im.Image] = im.Digest
		}
	}
	return out, nil
}

// normalize is ref as a full image name, without its tag or digest.
func normalize(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	first, _, slash := strings.Cut(name, "/")
	switch {
	case !slash:
		name = "docker.io/library/" + name
	case !strings.ContainsAny(first, ".:") && first != "localhost":
		name = "docker.io/" + name
	}
	return name
}

var clusterKinds = map[string]bool{"Namespace": true, "ClusterRole": true, "ClusterRoleBinding": true, "CustomResourceDefinition": true,
	"IngressClass": true, "PriorityClass": true, "StorageClass": true, "PersistentVolume": true}

func convert(o options, file string, pins map[string]string, box map[string]map[string]bool, images map[string]bool) ([]doc, error) {
	f, err := os.Open(file) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []doc
	dec := yaml.NewDecoder(f)
	for {
		var d doc
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if d == nil {
			continue
		}
		kind, _ := d["kind"].(string)
		md, _ := d["metadata"].(doc)
		if md == nil {
			return nil, fmt.Errorf("%s: a %s without metadata", file, kind)
		}
		name, _ := md["name"].(string)
		switch kind {
		case "Secret":
			if box[name] == nil {
				return nil, fmt.Errorf("the render carries the Secret %s, which product.yaml doesn't declare as a box secret: a bundle carries no secret value", name)
			}
			continue
		case "PersistentVolumeClaim":
			continue
		case "ConfigMap":
			if o.boxMaps[name] {
				return nil, fmt.Errorf("the render carries the ConfigMap %s, which the box writes from its settings (product.yaml box_settings)", name)
			}
			data, _ := d["data"].(doc)
			for k := range data {
				if o.secretKeys[k] {
					return nil, fmt.Errorf("the ConfigMap %s carries %s, which product.yaml keeps in a box secret: a secret setting never goes into a ConfigMap", name, k)
				}
			}
		}
		if !clusterKinds[kind] {
			md["namespace"] = o.Namespace
		}
		if kind == "Ingress" {
			sp, _ := d["spec"].(doc)
			delete(sp, "tls")
			rules, _ := sp["rules"].([]any)
			for _, r := range rules {
				if rm, ok := r.(doc); ok {
					delete(rm, "host")
				}
			}
		}
		if err := pod(o, d, kind, name, pins, box, images); err != nil {
			return nil, fmt.Errorf("%s %s: %w", kind, name, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func dig(d doc, keys ...string) doc {
	for _, k := range keys {
		next, _ := d[k].(doc)
		if next == nil {
			return nil
		}
		d = next
	}
	return d
}

func pod(o options, d doc, kind, name string, pins map[string]string, box map[string]map[string]bool, images map[string]bool) error {
	var ps, sts doc
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
		ps = dig(d, "spec", "template", "spec")
		if kind == "StatefulSet" {
			sts = dig(d, "spec")
		}
	case "CronJob":
		ps = dig(d, "spec", "jobTemplate", "spec", "template", "spec")
	case "Pod":
		ps = dig(d, "spec")
	default:
		return nil
	}
	if ps == nil {
		return errors.New("no pod spec")
	}
	var containers []doc
	for _, key := range []string{"initContainers", "containers"} {
		list, _ := ps[key].([]any)
		for _, c := range list {
			if cm, ok := c.(doc); ok {
				containers = append(containers, cm)
			}
		}
	}
	if len(containers) == 0 {
		return errors.New("no containers")
	}
	for _, c := range containers {
		ref, _ := c["image"].(string)
		img := normalize(ref)
		dgst, ok := pins[img]
		if !ok {
			return fmt.Errorf("the image %s isn't pinned in release.yaml", ref)
		}
		if _, have, _ := strings.Cut(ref, "@"); have != "" && "sha256:"+strings.TrimPrefix(have, "sha256:") != dgst {
			return fmt.Errorf("the image %s isn't the digest release.yaml pins (%s)", ref, dgst)
		}
		c["image"] = img + "@" + dgst
		c["imagePullPolicy"] = "Never"
		images[c["image"].(string)] = true
		if err := secretRefs(c, box); err != nil {
			return err
		}
	}
	mainImage, _ := ps["containers"].([]any)[0].(doc)["image"].(string)
	uid := 0
	if sc := dig(ps, "securityContext"); sc != nil {
		if u, ok := sc["runAsUser"].(int); ok {
			uid = u
		}
	}
	hostPath := func(vol doc) {
		vol["hostPath"] = doc{"path": path.Join(o.Data, strings.TrimPrefix(name, o.Namespace+"-")), "type": "DirectoryOrCreate"}
		init := doc{"name": "data-owner", "image": mainImage, "imagePullPolicy": "Never",
			"command": []any{"sh", "-c", fmt.Sprintf("chown %d:%d /data && chmod 0700 /data", uid, uid)},
			"securityContext": doc{"runAsUser": 0, "runAsNonRoot": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
				"capabilities": doc{"drop": []any{"ALL"}, "add": []any{"CHOWN", "FOWNER"}}},
			"resources":    doc{"requests": doc{"cpu": "10m", "memory": "16Mi"}, "limits": doc{"memory": "64Mi"}},
			"volumeMounts": []any{doc{"name": vol["name"], "mountPath": "/data"}}}
		inits, _ := ps["initContainers"].([]any)
		ps["initContainers"] = append([]any{init}, inits...)
	}
	vols, _ := ps["volumes"].([]any)
	for _, v := range vols {
		vm, _ := v.(doc)
		if vm == nil {
			continue
		}
		if _, ok := vm["persistentVolumeClaim"]; ok {
			delete(vm, "persistentVolumeClaim")
			hostPath(vm)
		}
		if sv := dig(vm, "secret"); sv != nil {
			sn, _ := sv["secretName"].(string)
			if opt, _ := sv["optional"].(bool); !opt && box[sn] == nil {
				return fmt.Errorf("it mounts the Secret %s, which product.yaml doesn't declare as a box secret", sn)
			}
		}
	}
	if sts != nil {
		if vct, ok := sts["volumeClaimTemplates"].([]any); ok {
			delete(sts, "volumeClaimTemplates")
			for _, t := range vct {
				tm, _ := t.(doc)
				vname, _ := dig(tm, "metadata")["name"].(string)
				vol := doc{"name": vname}
				hostPath(vol)
				vols = append(vols, vol)
			}
			ps["volumes"] = vols
		}
	}
	return nil
}

// secretRefs checks every Secret a container reads is a box secret.
func secretRefs(c doc, box map[string]map[string]bool) error {
	env, _ := c["env"].([]any)
	for _, e := range env {
		ref := dig(e.(doc), "valueFrom", "secretKeyRef")
		if ref == nil {
			continue
		}
		name, _ := ref["name"].(string)
		key, _ := ref["key"].(string)
		if opt, _ := ref["optional"].(bool); opt {
			continue
		}
		if box[name] == nil || !box[name][key] {
			return fmt.Errorf("it reads %s from the Secret %s, which product.yaml doesn't declare as a box secret key", key, name)
		}
	}
	from, _ := c["envFrom"].([]any)
	for _, e := range from {
		ref := dig(e.(doc), "secretRef")
		if ref == nil {
			continue
		}
		name, _ := ref["name"].(string)
		if opt, _ := ref["optional"].(bool); !opt && box[name] == nil {
			return fmt.Errorf("it loads the Secret %s, which product.yaml doesn't declare as a box secret", name)
		}
	}
	return nil
}

func key(d doc) string {
	return d["kind"].(string) + "/" + dig(d, "metadata")["name"].(string)
}

// split is the switch's stack: what only the on render has, and the
// ConfigMap with the settings SwitchFrom's ConfigMaps change.
func split(o options, off, on []doc, w io.Writer) ([]doc, error) {
	offBy := map[string]doc{}
	for _, d := range off {
		offBy[key(d)] = d
	}
	settings := map[string]any{}
	from := map[string]bool{}
	for _, cm := range o.SwitchFrom {
		from["ConfigMap/"+cm] = true
	}
	var extra []doc
	for _, d := range on {
		k := key(d)
		was, ok := offBy[k]
		switch {
		case !ok:
			extra = append(extra, d)
		case from[k]:
			a, _ := was["data"].(doc)
			b, _ := d["data"].(doc)
			for _, s := range union(a, b) {
				if reflect.DeepEqual(a[s], b[s]) {
					continue
				}
				v := b[s]
				if v == nil {
					v = ""
				}
				if prev, seen := settings[s]; seen && !reflect.DeepEqual(prev, v) {
					return nil, fmt.Errorf("the switch's setting %s differs between %s", s, strings.Join(o.SwitchFrom, " and "))
				}
				settings[s] = v
			}
		case !reflect.DeepEqual(was, d):
			if _, err := fmt.Fprintf(w, "stack: %s also differs with the switch on (not carried by the switch)\n", k); err != nil {
				return nil, err
			}
		}
	}
	cm := doc{"apiVersion": "v1", "kind": "ConfigMap", "metadata": doc{"name": o.SwitchConfigMap, "namespace": o.Namespace, "labels": partOf(o)}, "data": settings}
	return append([]doc{cm}, extra...), nil
}

func partOf(o options) doc { return doc{"app.kubernetes.io/part-of": o.Namespace} }

func union(a, b doc) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func write(p string, docs []doc) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- a build output, public manifests
		return err
	}
	var b strings.Builder
	for i, d := range docs {
		y, err := yaml.Marshal(d)
		if err != nil {
			return err
		}
		if i > 0 {
			b.WriteString("---\n")
		}
		b.Write(y)
	}
	return os.WriteFile(p, []byte(b.String()), 0o644) // #nosec G306 G703 -- as above
}
