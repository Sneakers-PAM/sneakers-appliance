// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package rootkey is the box's root key and its password pepper (spec 2,
// Section 2.3). The first start of accessd makes an ed25519 root key and
// 32 random bytes of pepper and seals both through init's KeyCustody, so
// in TPM mode a copied state volume yields neither. The private key is held
// in memory only; it signs the SSH user certificates of the keys the box
// issues and makes the root-shell codes. Only its public half is written,
// for sshd's TrustedUserCAKeys. The host CA, a second key sealed the same
// way, signs the box's SSH host certificates, so a client that trusts it
// (a @cert-authority line) never sees a host key prompt.
package rootkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
)

// The sealed items and the public file.
const (
	// SealedName is the KeyCustody item the root key is sealed as.
	SealedName = "root-key"
	// PepperName is the KeyCustody item the pepper is sealed as.
	PepperName = "access-pepper"
	// PepperSize is the pepper's length in bytes.
	PepperSize = 32
	// PublicFile is the root key's public half in the SSH directory, the
	// key sshd trusts as its only user CA.
	PublicFile = "root_key.pub"
	// HostCAName is the KeyCustody item the host CA is sealed as: a key of
	// its own, which signs only the box's SSH host certificates.
	HostCAName = "host-ca-key"
	// HostCAPublicFile is the host CA's public half in the SSH directory,
	// what a client's @cert-authority known_hosts line names.
	HostCAPublicFile = "host_ca.pub"
)

// codeDomain separates root-shell code signatures from anything else the
// root key signs.
const codeDomain = "sneakers-appliance root-shell code v1\x00"

// Sealer keeps the sealed items: init's KeyCustody on the box.
type Sealer interface {
	Seal(name string, secret []byte) error
	// Unseal returns the item; ok is false when it was never sealed.
	Unseal(name string) (secret []byte, ok bool, err error)
}

// Key is the loaded root key and pepper.
type Key struct {
	signer ssh.Signer
	priv   ed25519.PrivateKey
	pepper []byte
	hostCA ssh.Signer
}

// Load unseals the root key and the pepper, making and sealing each the
// first time, and writes the public half into sshDir. An item is used only
// once its sealed copy reads back.
func Load(sealer Sealer, sshDir string, lg log.Logger) (*Key, error) {
	if lg == nil {
		lg = log.Nop()
	}
	keyPEM, made, err := loadOrMake(sealer, SealedName, func() ([]byte, error) { return newKeyPEM("sneakers-appliance root key") })
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	if made {
		lg.Info("rootkey: made and sealed the root key")
	}
	raw, err := ssh.ParseRawPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("root key: the sealed item doesn't parse: %w", err)
	}
	priv, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("root key: the sealed item isn't an ed25519 key")
	}
	signer, err := ssh.NewSignerFromKey(*priv)
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	pepper, made, err := loadOrMake(sealer, PepperName, func() ([]byte, error) {
		b := make([]byte, PepperSize)
		_, err := rand.Read(b)
		return b, err
	})
	if err != nil {
		return nil, fmt.Errorf("pepper: %w", err)
	}
	if made {
		lg.Info("rootkey: made and sealed the password pepper")
	}
	if len(pepper) != PepperSize {
		return nil, fmt.Errorf("pepper: the sealed item is %d bytes, not %d", len(pepper), PepperSize)
	}
	caPEM, made, err := loadOrMake(sealer, HostCAName, func() ([]byte, error) { return newKeyPEM("sneakers-appliance host CA") })
	if err != nil {
		return nil, fmt.Errorf("host CA: %w", err)
	}
	if made {
		lg.Info("rootkey: made and sealed the SSH host CA")
	}
	hostCA, err := ssh.ParsePrivateKey(caPEM)
	if err != nil {
		return nil, fmt.Errorf("host CA: the sealed item doesn't parse: %w", err)
	}
	k := &Key{signer: signer, priv: *priv, pepper: pepper, hostCA: hostCA}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	if err := writeFile(filepath.Join(sshDir, PublicFile), ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	if err := writeFile(filepath.Join(sshDir, HostCAPublicFile), ssh.MarshalAuthorizedKey(hostCA.PublicKey()), 0o644); err != nil {
		return nil, fmt.Errorf("host CA: %w", err)
	}
	lg.Info("rootkey: loaded", log.F("fingerprint", k.Fingerprint()), log.F("hostCA", ssh.FingerprintSHA256(hostCA.PublicKey())))
	return k, nil
}

func loadOrMake(sealer Sealer, name string, mk func() ([]byte, error)) ([]byte, bool, error) {
	b, ok, err := sealer.Unseal(name)
	if err != nil {
		return nil, false, fmt.Errorf("unseal %s: %w", name, err)
	}
	if ok {
		return b, false, nil
	}
	if b, err = mk(); err != nil {
		return nil, false, err
	}
	if err := sealer.Seal(name, b); err != nil {
		return nil, false, fmt.Errorf("seal %s: %w", name, err)
	}
	back, ok, err := sealer.Unseal(name)
	if err != nil || !ok || !bytes.Equal(back, b) {
		return nil, false, fmt.Errorf("the sealed %s doesn't read back (%v)", name, err)
	}
	return b, true, nil
}

func newKeyPEM(comment string) ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// PublicKey is the root key's public half.
func (k *Key) PublicKey() ssh.PublicKey { return k.signer.PublicKey() }

// Fingerprint is the root key's SHA256: fingerprint.
func (k *Key) Fingerprint() string { return ssh.FingerprintSHA256(k.signer.PublicKey()) }

// Pepper is the password pepper.
func (k *Key) Pepper() []byte { return k.pepper }

// IssueUserCert signs an SSH user certificate for pub: principal admin,
// valid from validAfter to validBefore, permit-pty only.
func (k *Key) IssueUserCert(pub ssh.PublicKey, admin string, serial uint64, validAfter, validBefore time.Time) (*ssh.Certificate, error) {
	c := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("%s serial=%d fp=%s", admin, serial, ssh.FingerprintSHA256(pub)),
		ValidPrincipals: []string{admin},
		ValidAfter:      uint64(max(validAfter.Unix(), 0)),  // #nosec G115 -- clamped
		ValidBefore:     uint64(max(validBefore.Unix(), 0)), // #nosec G115 -- clamped
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := c.SignCert(rand.Reader, k.signer); err != nil {
		return nil, fmt.Errorf("root key: signing: %w", err)
	}
	return c, nil
}

// HostCAPublicKey is the host CA's public half.
func (k *Key) HostCAPublicKey() ssh.PublicKey { return k.hostCA.PublicKey() }

// SignHostCert signs an SSH host certificate for the host key pub, valid
// for principals (the box's names and addresses) from validAfter to
// validBefore.
func (k *Key) SignHostCert(pub ssh.PublicKey, principals []string, validAfter, validBefore time.Time) (*ssh.Certificate, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("host CA: %w", err)
	}
	var s uint64
	for _, b := range serial {
		s = s<<8 | uint64(b)
	}
	c := &ssh.Certificate{
		Key:             pub,
		Serial:          s,
		CertType:        ssh.HostCert,
		KeyId:           "host " + ssh.FingerprintSHA256(pub),
		ValidPrincipals: principals,
		ValidAfter:      uint64(max(validAfter.Unix(), 0)),  // #nosec G115 -- clamped
		ValidBefore:     uint64(max(validBefore.Unix(), 0)), // #nosec G115 -- clamped
	}
	if err := c.SignCert(rand.Reader, k.hostCA); err != nil {
		return nil, fmt.Errorf("host CA: signing: %w", err)
	}
	return c, nil
}

// Code is the root-shell code for msg: the first 40 bits of the root key's
// ed25519 signature over it, as XXXX-XXXX. ed25519 signatures are
// deterministic, so the same message always gives the same code and only
// this box's root key can make it.
func (k *Key) Code(msg []byte) string {
	sig := ed25519.Sign(k.priv, append([]byte(codeDomain), msg...))
	return onetime.Encode(sig, 8)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
