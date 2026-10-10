// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workerProfiles struct {
	Spec struct {
		WorkerProfiles []struct {
			Name   string         `yaml:"name"`
			Values map[string]any `yaml:"values"`
		} `yaml:"workerProfiles"`
	} `yaml:"spec"`
}

// The kubelet's image garbage collection, container-log rotation and disk
// eviction are set explicitly, in the box's own worker profile, and k0s
// starts with that profile (docs/disk-layout.md "Keeping the disk from
// filling"). The kubelet's default eviction (imagefs.available below 15%)
// would evict the product's pods at 85% full on the box's one state
// volume, before the box's own 90% alert; the box sets 5%.
func TestTheKubeletsDiskSettingsAreExplicit(t *testing.T) {
	b, err := os.ReadFile("k0s.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var c workerProfiles
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Spec.WorkerProfiles) != 1 || c.Spec.WorkerProfiles[0].Name != "sneakers" {
		t.Fatalf("worker profiles %+v", c.Spec.WorkerProfiles)
	}
	v := c.Spec.WorkerProfiles[0].Values
	for k, want := range map[string]any{
		"imageGCHighThresholdPercent": 90, "imageGCLowThresholdPercent": 85,
		"containerLogMaxSize": "10Mi", "containerLogMaxFiles": 3,
	} {
		if v[k] != want {
			t.Errorf("%s is %v, want %v", k, v[k], want)
		}
	}
	ev, _ := v["evictionHard"].(map[string]any)
	for k, want := range map[string]string{
		"nodefs.available": "5%", "imagefs.available": "5%", "nodefs.inodesFree": "5%", "imagefs.inodesFree": "5%", "memory.available": "100Mi",
	} {
		if ev[k] != want {
			t.Errorf("evictionHard[%s] is %v, want %s", k, ev[k], want)
		}
	}
	s, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(s), "--profile sneakers") {
		t.Error("k0s-interim doesn't start k0s with the sneakers worker profile")
	}
}
