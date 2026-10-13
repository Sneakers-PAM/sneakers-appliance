// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productimport

import (
	"strconv"
	"strings"

	log "github.com/Bugs5382/go-log"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// stepJob is what the box reads of a rendered step Job.
type stepJob struct {
	Metadata struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				Containers []struct {
					Resources struct {
						Limits map[string]string `yaml:"limits"`
					} `yaml:"resources"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// fits refuses a step whose memory limit is more than the box has
// available.
func (m *Manager) fits(step Step, doc string) error {
	if m.MemAvailable == nil {
		return nil
	}
	var j stepJob
	if err := yaml.Unmarshal([]byte(doc), &j); err != nil || len(j.Spec.Template.Spec.Containers) == 0 {
		return nil
	}
	limit := j.Spec.Template.Spec.Containers[0].Resources.Limits["memory"]
	need, ok := quantity(limit)
	if !ok {
		return nil
	}
	avail := m.MemAvailable()
	if avail < 0 || avail >= need {
		m.lg().Debug("productimport: the step fits in the box's memory", log.F("step", string(step)), log.F("limit", limit), log.F("available", avail))
		return nil
	}
	m.lg().Warn("productimport: a step was refused: the box hasn't the memory its limit needs", log.F("step", string(step)), log.F("limit", limit), log.F("available", avail))
	return codes.New(codes.NotAvailable, "the %s step may use up to %s of memory, and the box has %.1f GiB available; an import needs a box with that much free (docs/import.md)", step, limit, float64(avail)/(1<<30))
}

// quantity reads a Kubernetes memory quantity (4Gi, 512Mi, 1G, 1048576).
func quantity(q string) (int64, bool) {
	units := []struct {
		suffix string
		mult   int64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}}
	mult := int64(1)
	for _, u := range units {
		if n, ok := strings.CutSuffix(q, u.suffix); ok {
			q, mult = n, u.mult
			break
		}
	}
	n, err := strconv.ParseInt(q, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n * mult, true
}
