// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// Unit is one of the three things a box updates on its own: the Base OS
// (the root image, the UKI and the boot files), the Base Web (the :8443
// admin pages) and the Product (the product bundle).
type Unit string

// The units, as a header's unit field and the index's lists name them.
const (
	UnitBaseOS  Unit = "baseOS"
	UnitBaseWeb Unit = "baseWeb"
	UnitProduct Unit = "product"
)

// NameWeb is a Base Web package's header name. A box from before the units
// refuses it at Verify (UPGRADE_FORMAT), so it is never taken for a root
// image.
const NameWeb = "sneakers-appliance-web"

// MethodZstdPatch is the only patch method: the target file is the base
// file plus a `zstd --patch-from` delta, rebuilt byte for byte.
const MethodZstdPatch = "zstd-patch-from/1"

// BoxEpoch is the signing-key generation this build takes updates from (1
// is v0.x and v1.x). A header without an epoch reads as 1.
const BoxEpoch = 1

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	hashRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// PatchBase is the release a patch rebuilds from: its version, and the
// SHA-256 of its root image (the first RootSize bytes of the running slot)
// and of its UKI.
type PatchBase struct {
	Version    string `json:"version"`
	RootSHA256 string `json:"root_sha256"`
	RootSize   int64  `json:"root_size"`
	UKISHA256  string `json:"uki_sha256"`
}

// PatchTarget is what a patch rebuilds: the target release's root image
// and UKI by SHA-256 (the blobs its signed artifact pins), and the full
// .bin of the same release, which the box takes instead when the patch
// doesn't fit or doesn't rebuild.
type PatchTarget struct {
	Version    string `json:"version"`
	RootSHA256 string `json:"root_sha256"`
	UKISHA256  string `json:"uki_sha256"`
	FullBin    string `json:"full_bin,omitempty"`
}

// Range is the versions of another unit a package works with: Min
// inclusive, Before exclusive and optional.
type Range struct {
	Min    string `json:"min"`
	Before string `json:"before,omitempty"`
}

// Contains reports whether v is in the range.
func (r Range) Contains(v string) bool {
	if semver.Compare("v"+v, "v"+r.Min) < 0 {
		return false
	}
	return r.Before == "" || semver.Compare("v"+v, "v"+r.Before) < 0
}

// Text is the range in words: "0.3.0 to before 0.4.0", or "0.3.0 or
// newer" with no end.
func (r Range) Text() string {
	if r.Before == "" {
		return r.Min + " or newer"
	}
	return r.Min + " to before " + r.Before
}

func (r Range) check(what string) error {
	if !versionRE.MatchString(r.Min) {
		return codes.New(codes.UpgradeFormat, "%s needs a minimum version, not %q", what, r.Min)
	}
	if r.Before == "" {
		return nil
	}
	if !versionRE.MatchString(r.Before) {
		return codes.New(codes.UpgradeFormat, "%s ends at %q, which isn't a release version", what, r.Before)
	}
	if semver.Compare("v"+r.Before, "v"+r.Min) <= 0 {
		return codes.New(codes.UpgradeFormat, "%s ends at %s, before it starts at %s", what, r.Before, r.Min)
	}
	return nil
}

// DefaultRange is what a unit needs of another when its release says
// nothing more: the same major.minor, from X.Y.0 to before X.(Y+1).0. A lab
// range, and a pre-release's (an rc), takes pre-releases at both ends (lab
// versions are pre-releases of 0.0.0, and 0.2.0-rc.1 comes before 0.2.0).
func DefaultRange(version, channel string) Range {
	mm := semver.MajorMinor("v" + version)
	if mm == "" {
		return Range{}
	}
	var major, minor int
	_, _ = fmt.Sscanf(mm, "v%d.%d", &major, &minor)
	r := Range{Min: fmt.Sprintf("%d.%d.0", major, minor), Before: fmt.Sprintf("%d.%d.0", major, minor+1)}
	if channel == release.ChannelLab || semver.Prerelease("v"+version) != "" {
		r.Min += "-0"
		r.Before += "-0"
	}
	return r
}

// UnitOf is the unit a header updates. A sneakers-appliance header
// without a unit is the Base OS, as every one before the units was.
func UnitOf(h Header) Unit {
	switch {
	case h.Name == NameProduct || h.Kind == KindProduct:
		return UnitProduct
	case h.Name == NameWeb || h.Unit == UnitBaseWeb:
		return UnitBaseWeb
	}
	return UnitBaseOS
}

// Title is the unit as people read it.
func (u Unit) Title() string {
	switch u {
	case UnitBaseWeb:
		return "Base Web"
	case UnitProduct:
		return "Product"
	}
	return "Base OS"
}

// EpochOf is the header's key epoch; a header without one is epoch 1.
func (h Header) EpochOf() int {
	if h.Epoch == 0 {
		return 1
	}
	return h.Epoch
}

// CheckEpoch refuses a package of another key epoch than epoch, the box's
// (UPGRADE_EPOCH): a box never mixes units across epochs.
func CheckEpoch(h Header, epoch int) error {
	if h.EpochOf() == epoch {
		return nil
	}
	return codes.New(codes.UpgradeEpoch, "the %s %s is for key epoch %d; this box takes epoch %d. A new major needs its entitlement and a full .bin of every unit", UnitOf(h).Title(), h.Version, h.EpochOf(), epoch)
}

// NeedsBaseOS is the Base OS range a Base Web package needs: the one its
// header names, or the default for its version. Other units report false:
// the Base OS needs nothing, and a product's range is its min_base and
// max_base (AppliesTo).
func (h Header) NeedsBaseOS() (Range, bool) {
	if UnitOf(h) != UnitBaseWeb {
		return Range{}, false
	}
	if r, ok := h.Requires[UnitBaseOS]; ok {
		return r, true
	}
	return DefaultRange(h.Version, h.Channel), true
}

// FitsBaseOS refuses a Base Web package that doesn't fit the Base OS
// version running, with the fix in words (UPGRADE_COMPAT). offered is a
// Base OS version that would fit, such as the mirror's, or "".
func FitsBaseOS(h Header, running, offered string) error {
	r, ok := h.NeedsBaseOS()
	if !ok || r.Contains(running) {
		return nil
	}
	fix := "Install a Base OS in that range first"
	if mm := semver.MajorMinor("v" + r.Min); mm != "" && r.Before != "" {
		fix = "Install Base OS " + strings.TrimPrefix(mm, "v") + ".x first"
	}
	if offered != "" {
		fix += "; the mirror offers " + offered
	}
	return codes.New(codes.UpgradeCompat, "%s %s needs Base OS %s. This box runs Base OS %s. %s.", UnitOf(h).Title(), h.Version, r.Text(), running, fix)
}

// stamped is the version as a file name carries it: the build's commit is
// added once, unless the version (a lab one) already ends with it.
func stamped(version, commit string) string {
	if commit == "" {
		return version
	}
	g := "-g" + commit[:min(7, len(commit))]
	if strings.HasSuffix(version, g) {
		return version
	}
	return version + g
}

// LegacyFileName is the name a box before the units fetches a Base OS full
// release by: sneakers-appliance-<version>-<arch>[-LAB].bin. The release
// that bridges to the units publishes its Base OS file under it a second
// time.
func LegacyFileName(h Header) string {
	return fmt.Sprintf("%s-%s-%s%s.bin", Name, h.Version, h.Arch, labSuffix(h.Channel))
}

func labSuffix(channel string) string {
	if channel == release.ChannelLab {
		return "-LAB"
	}
	return ""
}

func (h Header) checkUnit() error {
	u := UnitOf(h)
	switch {
	case h.Name == NameWeb && h.Unit != UnitBaseWeb:
		return codes.New(codes.UpgradeFormat, "a %s header names the unit %s", NameWeb, UnitBaseWeb)
	case h.Unit == UnitBaseWeb && h.Name != NameWeb:
		return codes.New(codes.UpgradeFormat, "a Base Web header is named %s, not %s", NameWeb, h.Name)
	case h.Unit != "" && h.Unit != u:
		return codes.New(codes.UpgradeFormat, "a %s header can't be of unit %s", h.Name, h.Unit)
	case u == UnitBaseWeb && h.Kind != KindFull:
		return codes.New(codes.UpgradeFormat, "a Base Web package is full only")
	case h.Commit != "" && !commitRE.MatchString(h.Commit):
		return codes.New(codes.UpgradeFormat, "the commit %q isn't a hex commit id", h.Commit)
	case h.Inputs != "" && !hashRE.MatchString(h.Inputs):
		return codes.New(codes.UpgradeFormat, "the inputs digest %q isn't a SHA-256", h.Inputs)
	case h.Epoch < 0:
		return codes.New(codes.UpgradeFormat, "the epoch %d isn't a key epoch", h.Epoch)
	}
	for k, r := range h.Requires {
		if u != UnitBaseWeb || k != UnitBaseOS {
			return codes.New(codes.UpgradeFormat, "a %s names no requires.%s (a Base Web names requires.%s; a product, min_base)", u.Title(), k, UnitBaseOS)
		}
		if err := r.check("requires." + string(k)); err != nil {
			return err
		}
	}
	return h.checkPatch()
}

func (h Header) checkPatch() error {
	if h.Kind != KindPatch {
		if h.Method != "" || h.Base != nil || h.Target != nil {
			return codes.New(codes.UpgradeFormat, "only a patch names a method, a base or a target")
		}
		return nil
	}
	if h.Method != "" && h.Method != MethodZstdPatch {
		return codes.New(codes.UpgradeFormat, "the patch method %q isn't %s", h.Method, MethodZstdPatch)
	}
	if b := h.Base; b != nil {
		if len(h.Bases) != 1 || b.Version != h.Bases[0] {
			return codes.New(codes.UpgradeFormat, "a patch with a base names that one version in bases")
		}
		if !hashRE.MatchString(b.RootSHA256) || !hashRE.MatchString(b.UKISHA256) || b.RootSize <= 0 {
			return codes.New(codes.UpgradeFormat, "the patch's base names its root image's size and SHA-256 and its UKI's SHA-256")
		}
	}
	if t := h.Target; t != nil {
		if t.Version != h.Version {
			return codes.New(codes.UpgradeFormat, "the patch's target is %s; the header's version is %s", t.Version, h.Version)
		}
		if !hashRE.MatchString(t.RootSHA256) || !hashRE.MatchString(t.UKISHA256) {
			return codes.New(codes.UpgradeFormat, "the patch's target names its root image's and its UKI's SHA-256")
		}
		if t.FullBin != "" && !binNameRE.MatchString(t.FullBin) {
			return codes.New(codes.UpgradeFormat, "the patch's full .bin %q isn't a release file name", t.FullBin)
		}
	}
	return nil
}

// Applicable reports whether a patch carries what the box needs to rebuild
// its target: the base's and the target's hashes, and the method.
func (h Header) Applicable() error {
	if h.Kind != KindPatch {
		return nil
	}
	if h.Method == "" || h.Base == nil || h.Target == nil {
		return codes.New(codes.UpgradeFormat, "the patch %s doesn't name its method, base and target hashes, so it can't be rebuilt; take the full .bin", h.Version)
	}
	return nil
}

// binNameRE matches every published .bin name: the units' names, the
// products', and the names from before the units.
var binNameRE = regexp.MustCompile(`^sneakers-(appliance|appliance-baseOS|appliance-baseOS-patch|appliance-baseWeb|product)-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?-(amd64|arm64)(-LAB)?\.bin$`)

// ValidFileName reports whether name is shaped like a published .bin's.
// It's a filter for what a box fetches; the header decides.
func ValidFileName(name string) bool { return binNameRE.MatchString(name) }

var (
	fileRE   = regexp.MustCompile(`^sneakers-(?:appliance-baseOS-patch|appliance-baseOS|appliance-baseWeb|appliance|product)-(.+)-(?:amd64|arm64)(-LAB)?\.bin$`)
	commitGR = regexp.MustCompile(`-g[0-9a-f]{7}$`)
)

// ReleaseOf is the release version a published file belongs to, as the
// release source's tag names it: the version in its name (a patch's
// target), without the commit a production name adds. ok is false for a
// name that isn't a release file's.
func ReleaseOf(name string) (string, bool) {
	if !binNameRE.MatchString(name) {
		return "", false
	}
	m := fileRE.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	v := m[1]
	if i := strings.Index(v, "-from-"); i >= 0 && strings.HasPrefix(name, Name+"-baseOS-patch-") {
		v = v[:i]
	}
	if m[2] == "" {
		v = commitGR.ReplaceAllString(v, "")
	}
	return v, versionRE.MatchString(v)
}
