// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package switchroot

import "errors"

// errUnsupported is returned off Linux; the shim only runs as an initrd's
// /init. The stub lets the package build on a development host.
var errUnsupported = errors.New("switchroot: only supported on linux")

type stubSystem struct{}

// NewSystem returns a stub that fails every call off Linux.
func NewSystem() System { return stubSystem{} }

func (stubSystem) Mkdir(string, uint32) error                          { return errUnsupported }
func (stubSystem) Mount(string, string, string, uintptr, string) error { return errUnsupported }
func (stubSystem) Unmount(string, int) error                           { return errUnsupported }
func (stubSystem) ReadFile(string) ([]byte, error)                     { return nil, errUnsupported }
func (stubSystem) Partitions() ([]Partition, error)                    { return nil, errUnsupported }
func (stubSystem) AttachLoop(string) (string, error)                   { return "", errUnsupported }
func (stubSystem) Run([]string) error                                  { return errUnsupported }
func (stubSystem) Chdir(string) error                                  { return errUnsupported }
func (stubSystem) Chroot(string) error                                 { return errUnsupported }
func (stubSystem) Exec(string, []string, []string) error               { return errUnsupported }
func (stubSystem) Logf(string, ...any)                                 {}
