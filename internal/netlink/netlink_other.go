// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package netlink

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
)

var errUnsupported = errors.New("netlink: rtnetlink is unsupported on " + runtime.GOOS)

// LinkUp is unsupported off Linux.
func LinkUp(string) error { return errUnsupported }

// AddAddr is unsupported off Linux.
func AddAddr(string, netip.Prefix, uint32, uint32) error { return errUnsupported }

// DelAddr is unsupported off Linux.
func DelAddr(string, netip.Prefix) error { return errUnsupported }

// Addrs is unsupported off Linux.
func Addrs(string) ([]Addr, error) { return nil, errUnsupported }

// ReplaceDefaultRoute is unsupported off Linux.
func ReplaceDefaultRoute(string, netip.Addr, uint32, byte) error { return errUnsupported }

// DelDefaultRoute is unsupported off Linux.
func DelDefaultRoute(string, bool, uint32) error { return errUnsupported }

// Routes is unsupported off Linux.
func Routes(string) ([]Route, error) { return nil, errUnsupported }

// Neighbours is unsupported off Linux.
func Neighbours(string) ([]Neigh, error) { return nil, errUnsupported }

// Subscribe is unsupported off Linux.
func Subscribe(context.Context) (<-chan struct{}, error) { return nil, errUnsupported }
