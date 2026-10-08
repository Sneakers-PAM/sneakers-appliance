// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package sources is what the console reads and drives: init's custody,
// accessd's status and setup, the access backend's console API, netd, and
// init's service table. Where a backend isn't in this build yet (netd, the
// platform), its stub answers NotInstalled, never a
// success; each switches to the real one when its service appears in the
// service table, so the console needs no change when it lands.
package sources

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

// ServicesDir is init's service table in the root image.
const ServicesDir = "/usr/lib/sneakers/services.d"

// NotInstalled is the answer of a backend that isn't in this build yet.
type NotInstalled struct{ What string }

func (e NotInstalled) Error() string { return e.What + " isn't installed in this build yet" }

// IsNotInstalled reports whether err is a NotInstalled.
func IsNotInstalled(err error) bool {
	var ni NotInstalled
	return errors.As(err, &ni)
}

// Installed reports whether init's service table in dir has name.
func Installed(dir, name string) bool {
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, name+".yaml"))
	return err == nil
}

// what names a service the way the console says it.
var what = map[string]string{
	"netd":     "The network service",
	"sshd":     "The SSH service",
	"osadmin":  "The :8443 service",
	"accessd":  "The access service",
	"platform": "The platform",
}

func whatOf(name string) string {
	if w, ok := what[name]; ok {
		return w
	}
	return "The " + name + " service"
}

// Custody reads init's KeyCustody: the protection level and the custody
// mode.
type Custody struct {
	C initv1connect.KeyCustodyServiceClient
}

// Read returns the protection and the mode.
func (c Custody) Read(ctx context.Context) (keycustody.Protection, keycustody.Mode, error) {
	p, err := c.C.Protection(ctx, connect.NewRequest(&initv1.ProtectionRequest{}))
	if err != nil {
		return keycustody.Protection{}, "", err
	}
	prot := keycustody.Full()
	if p.Msg.GetLevel() == initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED {
		prot = keycustody.Reduced(keycustody.Reason(p.Msg.GetReason()))
	}
	m, err := c.C.Mode(ctx, connect.NewRequest(&initv1.ModeRequest{}))
	if err != nil {
		return prot, "", err
	}
	mode := keycustody.Mode("")
	switch m.Msg.GetMode() {
	case initv1.CustodyMode_CUSTODY_MODE_TPM:
		mode = keycustody.ModeTPM
	case initv1.CustodyMode_CUSTODY_MODE_KEYFILE:
		mode = keycustody.ModeKeyfile
	}
	return prot, mode, nil
}

// StatusView is one read of the status.
type StatusView struct {
	Status *osadminv1.GetStatusResponse
	// Saved is set when Status is accessd's cache, from while it was up.
	Saved time.Time
	// Err is why accessd didn't answer.
	Err error
}

// Status reads the :8443 Status data from accessd, as the console (root),
// falling back to accessd's cache.
type Status struct {
	Access    accessv1connect.AccessServiceClient
	CacheFile string
}

// Read returns the status.
func (s Status) Read(ctx context.Context) StatusView {
	r, err := s.Access.GetStatus(ctx, connect.NewRequest(&accessv1.GetStatusRequest{}))
	if err == nil {
		return StatusView{Status: r.Msg.GetStatus()}
	}
	v := StatusView{Err: err}
	if c, cerr := accessapi.ReadStatusCache(s.CacheFile); cerr == nil {
		v.Status, v.Saved = c.Status, c.Saved
	}
	return v
}

// HostKey is one SSH host key.
type HostKey struct{ Type, Fingerprint string }

// HostKeys reads the SSH host public keys in dir (the state volume's ssh
// directory); a box before setup's admin step has none.
func HostKeys(dir string) []HostKey {
	paths, _ := filepath.Glob(filepath.Join(dir, "ssh_host_*_key.pub"))
	sort.Strings(paths)
	var out []HostKey
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- a host public key under the state volume
		if err != nil {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			continue
		}
		out = append(out, HostKey{Type: pk.Type(), Fingerprint: ssh.FingerprintSHA256(pk)})
	}
	return out
}

// UnixClient is an HTTP client for a Connect service on a unix socket.
func UnixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}, Timeout: 30 * time.Second}
}
