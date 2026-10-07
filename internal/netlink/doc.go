// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package netlink configures NICs over raw rtnetlink: links up, IPv4 and
// IPv6 addresses with their lifetimes, default routes, and the address,
// route and neighbour tables read back, plus a subscription to the
// kernel's change notices. golang.org/x/sys/unix is all it needs.
//
// The message builders and parsers are
// OS-independent and unit-tested on any host; the socket I/O is Linux's.
package netlink
