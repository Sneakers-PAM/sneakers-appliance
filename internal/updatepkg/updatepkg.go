// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package updatepkg is the appliance's update package: one signed and
// encrypted `.bin` file per release and architecture (spec 5, Section 2.1).
// The box downloads it from the GitHub Release or an admin uploads the same
// file by hand; both paths read it here, the same way.
//
// The layout is
//
//	magic "SNKRBIN\x01"
//	uint32 big-endian header length, then the header (JSON)
//	uint32 big-endian bundle length, then the Sigstore bundle
//	the age ciphertext of the payload, to the end of the file
//
// The bundle is `cosign sign-blob --bundle` over the header bytes, made with
// the channel's release key. The header names the channel, the version, the
// kind (full or patch) and the SHA-256 and size of the ciphertext, so one
// signature covers the whole file. The payload is encrypted with age to the
// channel's update key. Lab and production each have their own release key
// and update key, so a lab file never verifies on a production box.
//
// A reader verifies the signature, the channel and the ciphertext digest
// before it decrypts anything.
package updatepkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"filippo.io/age"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
)

// Magic opens every update package.
const Magic = "SNKRBIN\x01"

// Name and Format are fixed header fields.
const (
	Name   = "sneakers-appliance"
	Format = 1
)

// maxSection caps the header and the bundle, so a hostile length can't make
// the reader allocate much.
const maxSection = 64 << 10

// Kind is a full version or a patch.
type Kind string

// The kinds.
const (
	KindFull  Kind = "full"
	KindPatch Kind = "patch"
)

// Header is the signed description of a package.
type Header struct {
	Format  int    `json:"format"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Kind    Kind   `json:"kind"`
	// Bases are the exact versions a patch applies to; a full version has
	// none.
	Bases   []string `json:"bases,omitempty"`
	Channel string   `json:"channel"`
	// Recipient is the hex SHA-256 of the age recipient the payload is
	// encrypted to.
	Recipient string `json:"recipient"`
	Payload   Digest `json:"payload"`
}

// Digest is the ciphertext's hash and size.
type Digest struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// check validates everything but the payload digest.
func (h Header) check() error {
	if !versionRE.MatchString(h.Version) {
		return codes.New(codes.UpgradeFormat, "the version %q isn't a release version", h.Version)
	}
	if h.Arch != "amd64" && h.Arch != "arm64" {
		return codes.New(codes.UpgradeFormat, "the architecture %q isn't amd64 or arm64", h.Arch)
	}
	if h.Channel != release.ChannelProduction && h.Channel != release.ChannelLab {
		return codes.New(codes.UpgradeFormat, "the channel %q isn't %s or %s", h.Channel, release.ChannelProduction, release.ChannelLab)
	}
	switch h.Kind {
	case KindFull:
		if len(h.Bases) > 0 {
			return codes.New(codes.UpgradeFormat, "a full version names no base versions")
		}
	case KindPatch:
		if len(h.Bases) == 0 {
			return codes.New(codes.UpgradeFormat, "a patch names the base versions it applies to")
		}
		for _, b := range h.Bases {
			if !versionRE.MatchString(b) {
				return codes.New(codes.UpgradeFormat, "the base version %q isn't a release version", b)
			}
		}
	default:
		return codes.New(codes.UpgradeFormat, "the kind %q isn't full or patch", h.Kind)
	}
	return nil
}

// Marshal is the header as it is signed and stored.
func (h Header) Marshal() ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("updatepkg: %w", err)
	}
	return b, nil
}

// AppliesTo reports whether the package can be applied on a box running
// version running. A full version always can, subject to the upgrade path
// rules elsewhere; a patch only on one of its exact base versions.
func (h Header) AppliesTo(running string) error {
	if h.Kind == KindPatch && !slices.Contains(h.Bases, running) {
		return codes.New(codes.UpgradePatchBase, "the patch %s is for %v; this box runs %s", h.Version, h.Bases, running)
	}
	return nil
}

// FileName is the package's published name: sneakers-appliance-<version>-<arch>.bin,
// with -LAB before the extension for a lab package.
func FileName(h Header) string {
	suffix := ""
	if h.Channel == release.ChannelLab {
		suffix = "-LAB"
	}
	return fmt.Sprintf("%s-%s-%s%s.bin", Name, h.Version, h.Arch, suffix)
}

// RecipientID is the fingerprint the header records for an age recipient.
func RecipientID(r *age.X25519Recipient) string {
	sum := sha256.Sum256([]byte(r.String()))
	return hex.EncodeToString(sum[:])
}

type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// Encrypt encrypts payload to r into ciphertext and returns h completed with
// the fixed fields, the recipient and the ciphertext digest, ready to sign.
func Encrypt(payload io.Reader, h Header, r *age.X25519Recipient, ciphertext io.Writer) (Header, error) {
	h.Format, h.Name = Format, Name
	if err := h.check(); err != nil {
		return Header{}, err
	}
	h.Recipient = RecipientID(r)
	sum, n := sha256.New(), &counter{}
	w, err := age.Encrypt(io.MultiWriter(ciphertext, sum, n), r)
	if err != nil {
		return Header{}, fmt.Errorf("updatepkg: %w", err)
	}
	if _, err := io.Copy(w, payload); err != nil {
		return Header{}, fmt.Errorf("updatepkg: %w", err)
	}
	if err := w.Close(); err != nil {
		return Header{}, fmt.Errorf("updatepkg: %w", err)
	}
	h.Payload = Digest{SHA256: hex.EncodeToString(sum.Sum(nil)), Size: n.n}
	return h, nil
}

// Seal writes the package: the magic, the signed header, its bundle and the
// ciphertext.
func Seal(w io.Writer, header, bundle []byte, ciphertext io.Reader) error {
	if len(header) > maxSection || len(bundle) > maxSection {
		return codes.New(codes.UpgradeFormat, "the header or the bundle is over %d bytes", maxSection)
	}
	var pre bytes.Buffer
	pre.WriteString(Magic)
	_ = binary.Write(&pre, binary.BigEndian, uint32(len(header))) // #nosec G115 -- bounded by maxSection
	pre.Write(header)
	_ = binary.Write(&pre, binary.BigEndian, uint32(len(bundle))) // #nosec G115 -- bounded by maxSection
	pre.Write(bundle)
	if _, err := w.Write(pre.Bytes()); err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	if _, err := io.Copy(w, ciphertext); err != nil {
		return fmt.Errorf("updatepkg: %w", err)
	}
	return nil
}

// Package is a read package. Header is trusted only after Verify.
type Package struct {
	Header   Header
	header   []byte
	bundle   []byte
	payload  *io.SectionReader
	verified bool
}

// Read parses the framing of the package in r (size bytes long). It checks
// nothing cryptographic; call Verify next.
func Read(r io.ReaderAt, size int64) (*Package, error) {
	off := int64(0)
	next := func(n int64) ([]byte, error) {
		if n < 0 || off+n > size {
			return nil, codes.New(codes.UpgradeFormat, "the file ends early")
		}
		b := make([]byte, n)
		if _, err := r.ReadAt(b, off); err != nil {
			return nil, codes.New(codes.UpgradeFormat, "the file can't be read: %v", err)
		}
		off += n
		return b, nil
	}
	section := func() ([]byte, error) {
		l, err := next(4)
		if err != nil {
			return nil, err
		}
		n := int64(binary.BigEndian.Uint32(l))
		if n > maxSection {
			return nil, codes.New(codes.UpgradeFormat, "a section is %d bytes, over %d", n, maxSection)
		}
		return next(n)
	}
	m, err := next(int64(len(Magic)))
	if err != nil || string(m) != Magic {
		return nil, codes.New(codes.UpgradeFormat, "the file isn't a sneakers-appliance update package")
	}
	p := &Package{}
	if p.header, err = section(); err != nil {
		return nil, err
	}
	if p.bundle, err = section(); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(p.header, &p.Header); err != nil {
		return nil, codes.New(codes.UpgradeFormat, "the header doesn't parse: %v", err)
	}
	p.payload = io.NewSectionReader(r, off, size-off)
	return p, nil
}

// Verify checks, in order, the header's signature against releaseKeyPEM,
// the channel against the box's, the header's rules, and the ciphertext's
// size and SHA-256 against the header. Only then may Decrypt run.
func (p *Package) Verify(releaseKeyPEM []byte, channel string) error {
	key, err := sigbundle.ParsePublicKey(releaseKeyPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	bd, err := sigbundle.Parse(p.bundle)
	if err != nil {
		return codes.New(codes.UpgradeSignature, "the package carries no readable signature")
	}
	if err := bd.Verify(key, sha256.Sum256(p.header)); err != nil {
		// The header isn't trusted here; it only picks the clearer refusal
		// for a package from the other channel.
		if p.Header.Channel != channel && (p.Header.Channel == release.ChannelLab || p.Header.Channel == release.ChannelProduction) {
			return codes.New(codes.UpgradeChannel, "this is a %s package; this box is %s", p.Header.Channel, channel)
		}
		return codes.New(codes.UpgradeSignature, "the package isn't signed by this box's release key")
	}
	if p.Header.Channel != channel {
		return codes.New(codes.UpgradeChannel, "this is a %s package; this box is %s", p.Header.Channel, channel)
	}
	if p.Header.Format != Format || p.Header.Name != Name {
		return codes.New(codes.UpgradeFormat, "the package is %s format %d; this box reads %s format %d", p.Header.Name, p.Header.Format, Name, Format)
	}
	if err := p.Header.check(); err != nil {
		return err
	}
	if p.payload.Size() != p.Header.Payload.Size {
		return codes.New(codes.UpgradeSignature, "the payload is %d bytes; the signed header says %d", p.payload.Size(), p.Header.Payload.Size)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, io.NewSectionReader(p.payload, 0, p.payload.Size())); err != nil {
		return codes.New(codes.UpgradeFormat, "the payload can't be read: %v", err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != p.Header.Payload.SHA256 {
		return codes.New(codes.UpgradeSignature, "the payload's SHA-256 isn't the one the signed header names")
	}
	p.verified = true
	return nil
}

// Decrypt writes the payload, decrypted with id, to w. It refuses a package
// Verify hasn't passed.
func (p *Package) Decrypt(id age.Identity, w io.Writer) error {
	if !p.verified {
		return codes.New(codes.UpgradeSignature, "the package hasn't been verified")
	}
	if x, ok := id.(*age.X25519Identity); ok && RecipientID(x.Recipient()) != p.Header.Recipient {
		return codes.New(codes.UpgradeDecrypt, "the package is encrypted to another update key")
	}
	r, err := age.Decrypt(io.NewSectionReader(p.payload, 0, p.payload.Size()), id)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return codes.New(codes.UpgradeDecrypt, "the package is encrypted to another update key")
		}
		return codes.New(codes.UpgradeDecrypt, "the package doesn't decrypt: %v", err)
	}
	if _, err := io.Copy(w, r); err != nil {
		return codes.New(codes.UpgradeDecrypt, "the package doesn't decrypt: %v", err)
	}
	return nil
}
