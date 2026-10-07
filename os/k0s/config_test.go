// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package k0s_test keeps k0s's baked config, containerd's sandbox pin, the
// lab image list and the service table in step (docs/k0s.md).
package k0s_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

type imageSpec struct {
	Image   string `yaml:"image"`
	Version string `yaml:"version"`
}

type clusterConfig struct {
	Spec struct {
		Images struct {
			DefaultPullPolicy string     `yaml:"default_pull_policy"`
			Pause             *imageSpec `yaml:"pause"`
			KubeProxy         *imageSpec `yaml:"kubeproxy"`
			CoreDNS           *imageSpec `yaml:"coredns"`
			KubeRouter        struct {
				CNI          *imageSpec `yaml:"cni"`
				CNIInstaller *imageSpec `yaml:"cniInstaller"`
			} `yaml:"kuberouter"`
		} `yaml:"images"`
		Telemetry struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"telemetry"`
		Storage struct {
			Type string `yaml:"type"`
			Etcd struct {
				ExtraArgs map[string]string `yaml:"extraArgs"`
			} `yaml:"etcd"`
		} `yaml:"storage"`
	} `yaml:"spec"`
}

var versionRE = regexp.MustCompile(`^[\w][\w.-]{0,127}@(sha256:[0-9a-f]{64})$`)

func config(t *testing.T) clusterConfig {
	t.Helper()
	b, err := os.ReadFile("k0s.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var c clusterConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// labImages reads build/lab/images.txt: group -> image -> digest.
func labImages(t *testing.T) map[string]map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "build", "lab", "images.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) != 4 {
			t.Fatalf("images.txt: %q isn't <group> <name> <image> <digest>", line)
		}
		if out[fs[0]] == nil {
			out[fs[0]] = map[string]string{}
		}
		out[fs[0]][fs[2]] = fs[3]
	}
	return out
}

func TestConfigPinsEveryImageByDigestAndNeverPulls(t *testing.T) {
	c := config(t)
	if c.Spec.Storage.Type != "etcd" || c.Spec.Storage.Etcd.ExtraArgs["name"] != "@NODE_NAME@" {
		t.Fatalf("storage is %q with etcd name %q; want etcd named after the box's node", c.Spec.Storage.Type, c.Spec.Storage.Etcd.ExtraArgs["name"])
	}
	if c.Spec.Images.DefaultPullPolicy != "Never" {
		t.Fatalf("default_pull_policy is %q; the box is airgapped, so it must be Never", c.Spec.Images.DefaultPullPolicy)
	}
	if c.Spec.Telemetry.Enabled {
		t.Fatal("telemetry is on")
	}
	im := c.Spec.Images
	specs := map[string]*imageSpec{"pause": im.Pause, "kubeproxy": im.KubeProxy, "coredns": im.CoreDNS,
		"kuberouter.cni": im.KubeRouter.CNI, "kuberouter.cniInstaller": im.KubeRouter.CNIInstaller}
	lab := labImages(t)["k0s"]
	seen := map[string]bool{}
	for name, s := range specs {
		if s == nil {
			t.Errorf("spec.images.%s isn't set, so k0s would use its own unpinned default", name)
			continue
		}
		m := versionRE.FindStringSubmatch(s.Version)
		if m == nil {
			t.Errorf("spec.images.%s.version %q isn't <tag>@sha256:<digest>", name, s.Version)
			continue
		}
		if lab[s.Image] != m[1] {
			t.Errorf("spec.images.%s is %s@%s; build/lab/images.txt bundles %q", name, s.Image, m[1], lab[s.Image])
		}
		seen[s.Image] = true
	}
	for image := range lab {
		if !seen[image] {
			t.Errorf("build/lab/images.txt bundles %s, which the k0s config doesn't use", image)
		}
	}
}

func TestContainerdSandboxIsTheBundledPause(t *testing.T) {
	c := config(t)
	b, err := os.ReadFile("containerd.toml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(string(b), "# k0s_managed=true") {
		t.Fatal("containerd.toml is marked k0s managed; k0s would try to rewrite it in the read-only /etc")
	}
	want := `sandbox = "` + c.Spec.Images.Pause.Image + ":" + c.Spec.Images.Pause.Version + `"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("containerd.toml doesn't pin the sandbox as %s", want)
	}
}

func TestHelloStackUsesOnlyTheBundledImage(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "lab", "overlay", "usr", "share", "sneakers", "manifests", "hello", "hello.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	third := labImages(t)["thirdParty"]
	images := regexp.MustCompile(`(?m)^\s*image:\s*(\S+)@(sha256:[0-9a-f]{64})\s*$`).FindAllStringSubmatch(string(b), -1)
	if len(images) == 0 {
		t.Fatal("the hello stack names no image by digest")
	}
	for _, m := range images {
		if third[m[1]] != m[2] {
			t.Errorf("the hello stack runs %s@%s, which build/lab/images.txt doesn't bundle", m[1], m[2])
		}
	}
	if n := strings.Count(string(b), "imagePullPolicy: Never"); n != len(images) {
		t.Errorf("%d of %d containers say imagePullPolicy: Never", n, len(images))
	}
}

func TestServiceTableRunsK0sInNormalOnly(t *testing.T) {
	m := fstest.MapFS{}
	for _, dir := range []string{"../rootfs/services.d", "../../build/lab/overlay/usr/lib/sneakers/services.d"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- the repo's own table
			if err != nil {
				t.Fatal(err)
			}
			m[services.Dir+"/"+e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	tbl, err := services.Load(m, services.Dir)
	if err != nil {
		t.Fatal(err)
	}
	k := tbl["k0s"]
	if k == nil {
		t.Fatal("the service table has no k0s")
	}
	if !slices.Equal(k.Phases, []phase.Phase{phase.Normal}) {
		t.Fatalf("k0s runs in %v; it needs the mounted state, so normal only", k.Phases)
	}
	if k.Exec != "/bin/sh" || !slices.Equal(k.Args, []string{"/usr/libexec/sneakers/k0s-interim", "run"}) {
		t.Errorf("k0s runs %s %v; want the interim launcher", k.Exec, k.Args)
	}
	if !slices.Equal(k.PreStart, []string{"/bin/sh", "/usr/libexec/sneakers/k0s-interim", "prepare"}) {
		t.Errorf("k0s pre-start is %v", k.PreStart)
	}
	if k.User != "" || k.Restart != services.RestartAlways || !slices.Contains(k.After, "netd") {
		t.Errorf("k0s runs as %q with restart %q after %v; want root, always, after netd", k.User, k.Restart, k.After)
	}
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exec /usr/bin/k0s controller --enable-worker --no-taints", "--config /run/sneakers/k0s/k0s.yaml", `--data-dir "$data"`, "data=/var/lib/k0s"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("k0s-interim doesn't start k0s with %q", want)
		}
	}
	if strings.Contains(string(b), "--single") {
		t.Error("k0s-interim starts k0s with --single, which can't take more nodes")
	}
	if h := tbl["lab-hook"]; h == nil || h.Restart != services.RestartNever {
		t.Errorf("the lab hook entry is %+v; want restart never", h)
	}
}
