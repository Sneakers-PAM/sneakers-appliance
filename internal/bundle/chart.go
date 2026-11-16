// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// ProductCharts holds the chart a product.yaml's resources section names:
// <name>-<version>.tgz, and <name>-<version>.manifest.json, the OCI manifest
// the registry serves for it.
const ProductCharts = "charts"

// helmChartMedia is the media type of a helm chart's archive layer.
const helmChartMedia = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

// Chart is a helm chart pinned in release.yaml: the registry digest is the
// OCI manifest's, which names the archive's layer by its own digest.
type Chart struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
	Digest     string `yaml:"digest"`
}

// maxChartFile bounds what the check reads of a chart archive.
const maxChartFile = 8 << 20

func chartMismatch(format string, args ...any) error {
	return codes.New(codes.KitBundleMismatch, format, args...)
}

// checkCharts holds charts/ to what the product names: with a resources
// section, exactly the archive and manifest of the chart release.yaml pins
// (the manifest hashes to the pin, names the archive's layer by its digest,
// and the archive's Chart.yaml is the pinned name and version); without
// one, no charts at all.
func checkCharts(fsys fs.FS, rel *Release, spec *productspec.Spec) error {
	entries, err := fs.ReadDir(fsys, ProductCharts)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return chartMismatch("the product bundle's %s can't be read: %v", ProductCharts, err)
	}
	if spec == nil || spec.Resources == nil {
		if len(entries) > 0 {
			return chartMismatch("the product bundle holds %s, but its product.yaml names no resources chart", ProductCharts)
		}
		return nil
	}
	key := spec.Resources.Chart
	pin := rel.Spec.ThirdParty[key].Chart
	if pin == nil {
		return chartMismatch("the product bundle's resources chart %s isn't pinned in its release.yaml", key)
	}
	if !digestRE.MatchString(pin.Digest) {
		return chartMismatch("release.yaml's chart %s has no sha256 digest", key)
	}
	base := pin.Name + "-" + pin.Version
	tgzPath, manPath := path.Join(ProductCharts, base+".tgz"), path.Join(ProductCharts, base+".manifest.json")
	for _, e := range entries {
		if p := path.Join(ProductCharts, e.Name()); p != tgzPath && p != manPath {
			return chartMismatch("the product bundle holds %s, which its chart %s never carries", p, key)
		}
	}
	tgz, err := fs.ReadFile(fsys, tgzPath)
	if err != nil {
		return chartMismatch("the product bundle has no %s, the chart its resources name", tgzPath)
	}
	man, err := fs.ReadFile(fsys, manPath)
	if err != nil {
		return chartMismatch("the product bundle has no %s, the manifest of its chart", manPath)
	}
	if got := hexSum(man); got != pin.Digest {
		return chartMismatch("the manifest %s has digest %s; release.yaml pins %s", manPath, got, pin.Digest)
	}
	var m struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(man, &m); err != nil {
		return chartMismatch("the manifest %s doesn't parse: %v", manPath, err)
	}
	var layers int
	for _, l := range m.Layers {
		if l.MediaType != helmChartMedia {
			continue
		}
		layers++
		if got := hexSum(tgz); got != l.Digest || int64(len(tgz)) != l.Size {
			return chartMismatch("the chart %s isn't the layer its manifest names (%s, %d bytes): it has %s, %d bytes", tgzPath, l.Digest, l.Size, got, len(tgz))
		}
	}
	if layers != 1 {
		return chartMismatch("the manifest %s has %d chart layers, not one", manPath, layers)
	}
	name, version, err := chartYAML(tgz)
	if err != nil {
		return chartMismatch("the chart %s: %v", tgzPath, err)
	}
	if name != pin.Name || version != pin.Version {
		return chartMismatch("the Chart.yaml in %s is %s %s; release.yaml pins %s %s", tgzPath, name, version, pin.Name, pin.Version)
	}
	return nil
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// chartYAML reads the name and version from the Chart.yaml at the top of a
// chart archive's one folder.
func chartYAML(tgz []byte) (name, version string, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return "", "", errors.New("isn't a gzip archive")
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxChartFile))
	for {
		h, err := tr.Next()
		if err != nil {
			return "", "", errors.New("has no Chart.yaml")
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != "Chart.yaml" || path.Dir(path.Dir(h.Name)) != "." {
			continue
		}
		var c struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return "", "", errors.New("has an unreadable Chart.yaml")
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return "", "", errors.New("has a Chart.yaml that doesn't parse")
		}
		return c.Name, c.Version, nil
	}
}
