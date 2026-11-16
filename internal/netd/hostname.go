// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// resolveWait bounds one DNS server's answer to a Resolve, UDP and TCP
// together.
const resolveWait = 5 * time.Second

// Resolution is what the box's DNS servers say about a name.
type Resolution struct {
	Addrs []netip.Addr
	// Found is false when the server answered that the name has no A or
	// AAAA record.
	Found bool
	// Server is the DNS server that answered.
	Server netip.Addr
}

// NormalHostname is a host name as the settings keep it: lower case, no
// final dot.
func NormalHostname(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func hostnameInvalid(name string) error {
	return codes.Wrap(codes.NetInvalid, &network.FieldError{Field: "hostname", Reason: fmt.Sprintf("%q isn't a fully qualified host name, such as appliance.example.org", name)})
}

// Resolve looks name up through the box's own DNS servers, each in turn
// until one answers. None answering, or none set or offered, is NET_DNS.
func (d *Daemon) Resolve(ctx context.Context, name string) (Resolution, error) {
	name = NormalHostname(name)
	if !network.ValidHostname(name) {
		return Resolution{}, hostnameInvalid(name)
	}
	d.mu.Lock()
	_, dns, _, _, _, _ := d.effective()
	d.mu.Unlock()
	lg := d.o.Logger
	if len(dns) == 0 {
		lg.Warn("netd: a name can't be looked up: no DNS server is set or offered", log.F("name", name))
		return Resolution{}, codes.New(codes.NetDNS, "no DNS server is set or offered, so %s can't be looked up", name)
	}
	var errs []error
	for _, srv := range dns {
		started := time.Now()
		sctx, cancel := context.WithTimeout(ctx, resolveWait)
		addrs, err := d.o.Sys.LookupDNS(sctx, srv, name)
		cancel()
		ms := time.Since(started).Milliseconds()
		switch {
		case errors.Is(err, ErrNoSuchName):
			lg.Info("netd: name looked up: not in DNS", log.F("name", name), log.F("server", srv.String()), log.F("ms", ms))
			return Resolution{Server: srv}, nil
		case err == nil:
			lg.Info("netd: name looked up", log.F("name", name), log.F("server", srv.String()), log.F("addresses", len(addrs)), log.F("ms", ms))
			return Resolution{Addrs: addrs, Found: true, Server: srv}, nil
		}
		lg.Warn("netd: a DNS server didn't answer a lookup; asking the next", log.F("name", name), log.F("server", srv.String()), log.F("ms", ms), log.F("error", err.Error()))
		errs = append(errs, err)
	}
	return Resolution{}, codes.Wrap(codes.NetDNS, fmt.Errorf("none of the box's DNS servers answered for %s: %w", name, errors.Join(errs...)))
}

// SetHostname sets the host name alone and keeps it at once, saved: no
// window, no stage, no confirm, every other setting as it is. Empty takes
// whatever DHCP offers. It returns the host name the settings held.
func (d *Daemon) SetHostname(name string) (string, error) {
	name = NormalHostname(name)
	if name != "" && !network.ValidHostname(name) {
		return "", hostnameInvalid(name)
	}
	prev, _ := d.Get()
	if prev.Hostname == name {
		d.o.Logger.Info("netd: host name already set", log.F("hostname", name))
		return prev.Hostname, nil
	}
	next := prev
	next.Hostname = name
	if err := d.keep(prev, next, nil); err != nil {
		d.o.Logger.Warn("netd: host name not set", log.F("hostname", name), log.F("error", err.Error()))
		return "", err
	}
	d.o.Logger.Info("netd: host name set alone and kept", log.F("hostname", name), log.F("was", prev.Hostname))
	return prev.Hostname, nil
}
