// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package elevated is sneakers-elevated (spec 2, Sections 2.8 and 3.4),
// the forced command of a maint login: before it gives a prompt it has
// accessd use the certificate up, then it runs the root shell on a pty it
// owns, records the whole session in both directions, shows the time left
// in the prompt, warns at 5 and 1 minutes, and ends the session at the
// approved length. It holds the time box itself, so the session ends even
// if accessd is down by then; and as the shell's parent, its own end ends
// the session.
package elevated

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// Accessd is the part of access.v1's ElevationService this uses.
type Accessd interface {
	BeginElevatedSession(context.Context, *connect.Request[accessv1.BeginElevatedSessionRequest]) (*connect.Response[accessv1.BeginElevatedSessionResponse], error)
	EndElevatedSession(context.Context, *connect.Request[accessv1.EndElevatedSessionRequest]) (*connect.Response[accessv1.EndElevatedSessionResponse], error)
}

// DefaultWarnings are when the session warns before its end.
var DefaultWarnings = []time.Duration{5 * time.Minute, time.Minute}

// Options wire a session.
type Options struct {
	Accessd Accessd
	// Login is what sshd says about the login: its certificate and the
	// client's address.
	Login accessapi.Login
	// Shell is the root shell and its arguments; empty is /bin/sh -l.
	Shell []string
	// Audit is the OS audit log the recording's chunk hashes go to; its
	// directory holds the recordings.
	Audit *osaudit.Log
	// In and Out are the SSH session's terminal.
	In  io.Reader
	Out io.Writer
	// Resize, when set, copies the SSH terminal's size onto the shell's
	// pty now and whenever it changes, until ctx ends.
	Resize   func(ctx context.Context, pty *os.File)
	Warnings []time.Duration
	PID      int
	Logger   log.Logger
}

// Result is how the session ended.
type Result struct {
	ID     string
	Reason string
	SHA256 string
}

// Run runs one elevated session. terminated is cancelled when accessd (an
// owner's terminate) sends SIGTERM.
func Run(ctx, terminated context.Context, o Options) (Result, error) {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if len(o.Shell) == 0 {
		o.Shell = []string{"/bin/sh", "-l"}
	}
	if o.Warnings == nil {
		o.Warnings = DefaultWarnings
	}
	if _, ok := o.Login.Key.(*ssh.Certificate); !ok {
		return Result{}, errors.New("this login didn't use an elevation certificate")
	}
	begin, err := o.Accessd.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Certificate: o.Login.KeyLine, Pid: int32(min(o.PID, 1<<30))})) // #nosec G115 -- clamped
	if err != nil {
		var ce *connect.Error
		if errors.As(err, &ce) && ce.Code() == connect.CodeUnavailable {
			return Result{}, errors.New(accessapi.Unavailable)
		}
		return Result{}, fmt.Errorf("the certificate wasn't accepted: %w", err)
	}
	e := begin.Msg.GetElevation()
	ends := begin.Msg.GetEnds().AsTime()
	res := Result{ID: e.GetId()}
	o.Logger.Info("elevated: session begins", log.F("id", res.ID), log.F("admin", e.GetAdmin()), log.F("ends", ends))

	path := osaudit.RecordingPath(o.Audit.Dir(), res.ID)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the recording of the request accessd named
	if err != nil {
		return res, fmt.Errorf("the session can't be recorded, so it doesn't start: %w", err)
	}
	rec := osaudit.NewRecorder(f, o.Audit, res.ID)
	reason, runErr := session(ctx, terminated, o, rec, e.GetAdmin(), ends)
	res.Reason = reason
	if err := rec.Close(reason); err != nil {
		o.Logger.Error(err, "elevated: the recording's end wasn't logged", log.F("id", res.ID))
	}
	if err := f.Close(); err != nil {
		o.Logger.Error(err, "elevated: the recording wasn't closed", log.F("id", res.ID))
	}
	res.SHA256 = fileSHA(path)
	endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if _, err := o.Accessd.EndElevatedSession(endCtx, connect.NewRequest(&accessv1.EndElevatedSessionRequest{Id: res.ID, Reason: reason, RecordingSha256: res.SHA256})); err != nil {
		o.Logger.Error(err, "elevated: accessd didn't take the session's end", log.F("id", res.ID))
	}
	o.Logger.Info("elevated: session ended", log.F("id", res.ID), log.F("reason", reason))
	return res, runErr
}

// session runs the shell on its own pty until it exits, the time box runs
// out or the session is terminated, and returns which.
func session(ctx, terminated context.Context, o Options, rec *osaudit.Recorder, admin string, ends time.Time) (string, error) {
	master, slave, err := openPTY()
	if err != nil {
		return elevation.ReasonExit, err
	}
	defer func() { _ = master.Close() }()
	cmd := exec.Command(o.Shell[0], o.Shell[1:]...) // #nosec G204 -- the fixed root shell
	cmd.Env = []string{
		"HOME=/root", "USER=root", "LOGNAME=root", "SHELL=" + o.Shell[0],
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=" + termOf(os.Getenv("TERM")),
		"SNEAKERS_ELEVATION=" + admin,
		"SNEAKERS_ELEVATION_ENDS=" + strconv.FormatInt(ends.Unix(), 10),
		// busybox ash expands the prompt (ASH_EXPAND_PRMT), so it shows the
		// minutes left at each prompt.
		`PS1=[elevated $(( (SNEAKERS_ELEVATION_ENDS - $(date +%s)) / 60 )) min left] \w # `,
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		return elevation.ReasonExit, fmt.Errorf("the shell didn't start: %w", err)
	}
	_ = slave.Close()
	pctx, stopResize := context.WithCancel(ctx)
	defer stopResize()
	if o.Resize != nil {
		go o.Resize(pctx, master)
	}

	var outMu sync.Mutex
	say := func(msg string) {
		b := []byte("\r\n[sneakers-elevated] " + msg + "\r\n")
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = o.Out.Write(b)
		_, _ = rec.Write(b)
	}
	say(fmt.Sprintf("Root shell for %s, recorded. It ends at %s UTC.", admin, ends.UTC().Format("15:04:05")))
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := o.In.Read(buf)
			if n > 0 {
				if rerr := rec.Input(buf[:n]); rerr != nil {
					o.Logger.Error(rerr, "elevated: the recording failed; ending the session")
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					return
				}
				_, _ = master.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		buf := make([]byte, 32*1024)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				outMu.Lock()
				_, _ = o.Out.Write(buf[:n])
				_, rerr := rec.Write(buf[:n])
				outMu.Unlock()
				if rerr != nil {
					o.Logger.Error(rerr, "elevated: the recording failed; ending the session")
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	var timers []*time.Timer
	for _, w := range o.Warnings {
		at := time.Until(ends.Add(-w))
		if at <= 0 {
			continue
		}
		left := w
		timers = append(timers, time.AfterFunc(at, func() {
			say(fmt.Sprintf("%s left; the session ends at %s UTC.", left.Round(time.Second), ends.UTC().Format("15:04:05")))
		}))
	}
	defer func() {
		for _, t := range timers {
			t.Stop()
		}
	}()
	box := time.NewTimer(time.Until(ends))
	defer box.Stop()

	reason := elevation.ReasonExit
	select {
	case <-exited:
	case <-box.C:
		reason = elevation.ReasonTimeBox
	case <-terminated.Done():
		reason = elevation.ReasonTerminated
	case <-ctx.Done():
		// The client went away (SIGHUP): the session ends as an exit.
	}
	if reason != elevation.ReasonExit || ctx.Err() != nil {
		if msg := map[string]string{elevation.ReasonTimeBox: "The approved time is up; the session ends now.", elevation.ReasonTerminated: "An owner ended this session."}[reason]; msg != "" {
			say(msg)
		}
		// The shell leads its own session and process group (Setsid), so
		// this ends everything it started.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-exited
	}
	select {
	case <-copied:
	case <-time.After(2 * time.Second):
	}
	return reason, nil
}

func termOf(t string) string {
	for _, c := range t {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return "vt100"
		}
	}
	if t == "" || len(t) > 32 {
		return "vt100"
	}
	return t
}

func fileSHA(path string) string {
	f, err := os.Open(path) // #nosec G304 -- the session's own recording
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
