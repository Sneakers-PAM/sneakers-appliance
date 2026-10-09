// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package ppk writes an ed25519 key and its OpenSSH user certificate as a
// PuTTY private key file, format version 3, with the certificate embedded
// (PuTTY 0.78 or later reads it; the key type is the certificate's,
// ssh.CertAlgoED25519v01). PuTTY and MobaXterm then send the
// certificate with the key, as sshd's certificate-only login needs.
//
// The file is unencrypted, like the OpenSSH private key the box hands out
// next to it: with no passphrase, format 3's MAC is HMAC-SHA-256 under an
// empty key.
package ppk

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// lineWidth is how many base64 characters PuTTY puts on a line.
const lineWidth = 64

// Marshal returns the .ppk for priv with cert embedded. cert must certify
// priv's public key; comment is one line.
func Marshal(priv ed25519.PrivateKey, cert *ssh.Certificate, comment string) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ppk: an ed25519 private key is %d bytes", ed25519.PrivateKeySize)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("ppk: %w", err)
	}
	if cert == nil || cert.Key == nil || string(cert.Key.Marshal()) != string(pub.Marshal()) {
		return nil, fmt.Errorf("ppk: the certificate isn't for this key")
	}
	if strings.ContainsAny(comment, "\r\n") {
		return nil, fmt.Errorf("ppk: the comment is one line")
	}
	alg := cert.Type()
	pubBlob := cert.Marshal()
	privBlob := sshString(leUnsigned(priv.Seed()))
	const encryption = "none"

	mac := hmac.New(sha256.New, nil)
	for _, f := range [][]byte{[]byte(alg), []byte(encryption), []byte(comment), pubBlob, privBlob} {
		_, _ = mac.Write(sshString(f))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "PuTTY-User-Key-File-3: %s\n", alg)
	fmt.Fprintf(&b, "Encryption: %s\n", encryption)
	fmt.Fprintf(&b, "Comment: %s\n", comment)
	writeLines(&b, "Public-Lines", pubBlob)
	writeLines(&b, "Private-Lines", privBlob)
	fmt.Fprintf(&b, "Private-MAC: %s\n", hex.EncodeToString(mac.Sum(nil)))
	return []byte(b.String()), nil
}

func writeLines(b *strings.Builder, name string, blob []byte) {
	s := base64.StdEncoding.EncodeToString(blob)
	n := (len(s) + lineWidth - 1) / lineWidth
	fmt.Fprintf(b, "%s: %d\n", name, n)
	for len(s) > lineWidth {
		b.WriteString(s[:lineWidth] + "\n")
		s = s[lineWidth:]
	}
	b.WriteString(s + "\n")
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b))) // #nosec G115 -- a key-sized blob
	return append(out, b...)
}

// leUnsigned is PuTTY's form of an EdDSA private key: the seed read as a
// little-endian integer, written without its high zero bytes.
func leUnsigned(seed []byte) []byte {
	n := len(seed)
	for n > 0 && seed[n-1] == 0 {
		n--
	}
	return seed[:n]
}
