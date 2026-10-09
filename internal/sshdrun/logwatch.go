// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun

import (
	"bytes"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// failedKey is sshd's line for a refused public key (LogLevel VERBOSE).
// A certificate shows as <type>-CERT followed by its ID; a bare key as its
// type and fingerprint only.
var failedKey = regexp.MustCompile(`Failed publickey for (\S+) from (\S+) port \d+ ssh2: ([A-Z0-9]+(?:-SK)?) (SHA256:[A-Za-z0-9+/=]+)$`)

// maxLine caps a buffered partial line; sshd's lines are far shorter.
const maxLine = 16 << 10

// LogWatchOptions wire a LogWatch.
type LogWatchOptions struct {
	// StateDir is /var/lib/sneakers: access/store.json names the issued keys.
	StateDir string
	Audit    osaudit.Appender
	// Out gets everything sshd logs, unchanged.
	Out    io.Writer
	Logger log.Logger
	Now    func() time.Time
}

// LogWatch is sshd's log on its way to Out: a box-issued key sent without
// its certificate is refused by sshd with no word to the client beyond
// "publickey", so each such refusal is audited (ssh.login, refused,
// ACCESS_KEY_NO_CERTIFICATE) for :8443 to show why the login failed.
type LogWatch struct {
	o   LogWatchOptions
	mu  sync.Mutex
	buf []byte
}

// NewLogWatch returns a LogWatch.
func NewLogWatch(o LogWatchOptions) *LogWatch {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &LogWatch{o: o}
}

// Write passes p to Out and reads the whole lines in it.
func (w *LogWatch) Write(p []byte) (int, error) {
	n, err := w.o.Out.Write(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.line(string(bytes.TrimRight(w.buf[:i], "\r")))
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > maxLine {
		w.buf = w.buf[:0]
	}
	return n, err
}

func (w *LogWatch) line(l string) {
	m := failedKey.FindStringSubmatch(l)
	if m == nil {
		return
	}
	user, source, fp := m[1], m[2], m[4]
	st, err := access.ReadState(filepath.Join(w.o.StateDir, "access"))
	if err != nil {
		w.o.Logger.Warn("sshd-run: a refused key wasn't looked up", log.F("error", err.Error()))
		return
	}
	for _, a := range st.Admins {
		for _, k := range a.Keys {
			if k.Via != access.ViaIssued || k.Fingerprint != fp {
				continue
			}
			w.audit(user, source, a.Name, k)
			return
		}
	}
	w.o.Logger.Debug("sshd-run: a refused key isn't one the box issued", log.F("user", user), log.F("source", source), log.F("key", fp))
}

func (w *LogWatch) audit(user, source, owner string, k access.AdminKey) {
	w.o.Logger.Warn("sshd-run: a box-issued key was sent without its certificate", log.F("user", user), log.F("owner", owner), log.F("source", source), log.F("key", k.Fingerprint), log.F("serial", k.Serial))
	if w.o.Audit == nil {
		return
	}
	e := osaudit.Entry{Time: w.o.Now().UTC(), Actor: user, KeyFP: k.Fingerprint, Source: source, Action: "ssh.login", Target: owner,
		Outcome: "refused", Code: codes.Symbol(codes.AccessKeyNoCertificate),
		Detail: map[string]string{"reason": "the box-issued key was sent without its certificate", "serial": strconv.FormatUint(k.Serial, 10)}}
	if err := w.o.Audit.Append(e); err != nil {
		w.o.Logger.Error(err, "sshd-run: the refused key wasn't audited")
	}
}
