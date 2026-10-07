// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

// Package netlink configures NICs over raw rtnetlink: links up, IPv4 and
// IPv6 addresses with their lifetimes, default routes, and the address,
// route and neighbour tables read back, plus a subscription to the
// kernel's change notices. golang.org/x/sys/unix is all it needs.
//
// Ported from CryptOS-PKI internal/init/netlink (IPv4 static only there)
// and extended for IPv6, lifetimes, route and neighbour dumps and the
// change subscription. The message builders and parsers are
// OS-independent and unit-tested on any host; the socket I/O is Linux's.
package netlink
