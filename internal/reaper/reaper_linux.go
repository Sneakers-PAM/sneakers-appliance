// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package reaper is the child reaper and process runner PID 1 uses.
package reaper

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// Reaper is the services.Runner PID 1 uses. As PID 1, init inherits every orphan and
// must reap them all, so one loop owns every wait4: it reaps any exited
// child and hands the status to whoever started it. os/exec can't be used
// beside it, because its Wait would race the loop for the same children.
type Reaper struct {
	mu      sync.Mutex
	waiting map[int]chan error
	sigs    chan os.Signal
}

var (
	reaperOnce sync.Once
	theReaper  *Reaper
)

// NewReaper returns the process's one reaper, starting its loop on first
// use. There can only be one: two loops would reap each other's children.
func NewReaper() *Reaper {
	reaperOnce.Do(func() {
		theReaper = &Reaper{waiting: map[int]chan error{}, sigs: make(chan os.Signal, 16)}
		signal.Notify(theReaper.sigs, syscall.SIGCHLD)
		go theReaper.loop()
	})
	return theReaper
}

func (r *Reaper) loop() {
	for range r.sigs {
		r.reap()
	}
}

func (r *Reaper) reap() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
		var res error
		switch {
		case ws.Exited() && ws.ExitStatus() == 0:
		case ws.Exited():
			res = fmt.Errorf("exit status %d", ws.ExitStatus())
		case ws.Signaled():
			res = fmt.Errorf("signal: %s", ws.Signal())
		default:
			res = fmt.Errorf("wait status %v", ws)
		}
		// Start holds the lock from fork to registration, so a child of
		// ours is always registered by the time this lock is taken; any
		// other pid is an orphan, reaped and dropped.
		r.mu.Lock()
		if ch, ok := r.waiting[pid]; ok {
			delete(r.waiting, pid)
			ch <- res
		}
		r.mu.Unlock()
	}
}

type reaped struct {
	p    *os.Process
	done chan error
	once sync.Once
	err  error
}

func (p *reaped) Wait() error {
	p.once.Do(func() { p.err = <-p.done })
	return p.err
}

func (p *reaped) Signal(sig os.Signal) error { return p.p.Signal(sig) }

// Start starts argv with init's console as its output.
func (r *Reaper) Start(argv []string) (services.Process, error) {
	return r.start(argv, nil)
}

// StartAs starts argv like Start, under uid and gid with no supplementary
// groups and caps as its ambient capabilities.
func (r *Reaper) StartAs(argv []string, uid, gid uint32, caps []uintptr) (services.Process, error) {
	return r.start(argv, &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, AmbientCaps: caps})
}

// StartConsole starts argv with stdout, a claim on the consoles, as its
// standard output; its standard error stays on init's shared output.
func (r *Reaper) StartConsole(argv []string, stdout *os.File) (services.Process, error) {
	return r.startWith(argv, stdout, nil)
}

func (r *Reaper) start(argv []string, sys *syscall.SysProcAttr) (services.Process, error) {
	return r.startWith(argv, os.Stdout, sys)
}

func (r *Reaper) startWith(argv []string, stdout *os.File, sys *syscall.SysProcAttr) (services.Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := os.StartProcess(argv[0], argv, &os.ProcAttr{Files: []*os.File{os.Stdin, stdout, os.Stderr}, Sys: sys})
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	r.waiting[p.Pid] = done
	// The reaper, not os.Process.Wait, collects it.
	return &reaped{p: p, done: done}, nil
}

// Run runs argv to completion, killing it if ctx ends first.
func (r *Reaper) Run(ctx context.Context, argv []string) error {
	p, err := r.Start(argv)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- p.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = p.Signal(syscall.SIGKILL)
		<-done
		return ctx.Err()
	}
}

// Output runs argv to completion with stdin (nil for none) as its input
// and returns what it wrote to stdout and stderr, killing it if ctx ends
// first: os/exec's Output, with the reaper collecting the child.
func (r *Reaper) Output(ctx context.Context, stdin io.Reader, argv []string) (stdout, stderr []byte, err error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW)
		return nil, nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW, outR, outW)
		return nil, nil, err
	}
	r.mu.Lock()
	p, err := os.StartProcess(argv[0], argv, &os.ProcAttr{Files: []*os.File{inR, outW, errW}})
	var done chan error
	if err == nil {
		done = make(chan error, 1)
		r.waiting[p.Pid] = done
	}
	r.mu.Unlock()
	// The child holds its own copies now.
	closeAll(inR, outW, errW)
	if err != nil {
		closeAll(inW, outR, errR)
		return nil, nil, err
	}
	go func() {
		if stdin != nil {
			_, _ = io.Copy(inW, stdin)
		}
		_ = inW.Close()
	}()
	var outBuf, errBuf bytes.Buffer
	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); _, _ = io.Copy(&outBuf, outR) }()
	go func() { defer copies.Done(); _, _ = io.Copy(&errBuf, errR) }()
	var res error
	select {
	case res = <-done:
	case <-ctx.Done():
		_ = p.Signal(syscall.SIGKILL)
		<-done
		res = ctx.Err()
	}
	copies.Wait()
	closeAll(outR, errR)
	return outBuf.Bytes(), errBuf.Bytes(), res
}

func closeAll(fs ...*os.File) {
	for _, f := range fs {
		_ = f.Close()
	}
}

// Exists reports whether path exists.
func (r *Reaper) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var (
	_ services.Runner     = (*Reaper)(nil)
	_ services.UserRunner = (*Reaper)(nil)
)
