// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package network is netd's settings model: the management and optional
// service interface, IPv4 and IPv6 modes, hostname, DNS, NTP, the
// management allow-list and the cluster ranges, with the validation of spec
// 2 Section 2.2 and the 120-second auto-revert of Section 3.5.
package network

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Mode4 is how an interface gets its IPv4 address.
type Mode4 string

// The IPv4 modes.
const (
	V4DHCP   Mode4 = "dhcp"
	V4Static Mode4 = "static"
	V4Off    Mode4 = "off"
)

// Mode6 is how an interface gets its IPv6 address.
type Mode6 string

// The IPv6 modes. SLAAC also reads RDNSS from router advertisements.
const (
	V6SLAAC  Mode6 = "slaac"
	V6DHCPv6 Mode6 = "dhcpv6"
	V6Static Mode6 = "static"
	V6Off    Mode6 = "off"
)

// The limits of Section 2.2.
const (
	MaxDNS       = 3
	MaxNTP       = 4
	MaxSearch    = 6
	MaxAllowList = 64
)

// Family4 is one interface's IPv4 settings.
type Family4 struct {
	Mode    Mode4        `yaml:"mode" json:"mode"`
	Address netip.Prefix `yaml:"address,omitempty" json:"address,omitzero"`
	Gateway netip.Addr   `yaml:"gateway,omitempty" json:"gateway,omitzero"`
}

// Family6 is one interface's IPv6 settings.
type Family6 struct {
	Mode    Mode6        `yaml:"mode" json:"mode"`
	Address netip.Prefix `yaml:"address,omitempty" json:"address,omitzero"`
	Gateway netip.Addr   `yaml:"gateway,omitempty" json:"gateway,omitzero"`
}

// Interface is one NIC and its address settings.
type Interface struct {
	Name string  `yaml:"name" json:"name"`
	IPv4 Family4 `yaml:"ipv4" json:"ipv4"`
	IPv6 Family6 `yaml:"ipv6" json:"ipv6"`
}

// ClusterRanges are the k0s pod and service ranges; they must not overlap
// the networks the box sits on.
type ClusterRanges struct {
	Pods     netip.Prefix `yaml:"pods" json:"pods"`
	Services netip.Prefix `yaml:"services" json:"services"`
}

// Settings is everything netd applies. Empty Hostname, DNS and NTP mean
// "whatever DHCP and RA offer".
type Settings struct {
	// Management is where 22 and 8443 listen.
	Management Interface `yaml:"management" json:"management"`
	// Service, when set, carries the product's 443 and 80 (spec 3); 22 and
	// 8443 never listen there.
	Service  *Interface   `yaml:"service,omitempty" json:"service,omitempty"`
	Hostname string       `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	DNS      []netip.Addr `yaml:"dns,omitempty" json:"dns,omitempty"`
	Search   []string     `yaml:"search,omitempty" json:"search,omitempty"`
	NTP      []string     `yaml:"ntp,omitempty" json:"ntp,omitempty"`
	// AllowList holds the prefixes 22 and 8443 accept. Empty during setup
	// means any source on the management interface.
	AllowList  []netip.Prefix `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	TimeZone   string         `yaml:"timeZone,omitempty" json:"timeZone,omitempty"`
	HTTPSProxy string         `yaml:"httpsProxy,omitempty" json:"httpsProxy,omitempty"`
	Cluster    ClusterRanges  `yaml:"cluster" json:"cluster"`
}

// The k0s defaults.
var (
	DefaultPods     = netip.MustParsePrefix("10.244.0.0/16") // scrub:allow=private-ip -- the k0s default
	DefaultServices = netip.MustParsePrefix("10.96.0.0/12")  // scrub:allow=private-ip -- the k0s default
)

// Defaults is the first-boot screen's starting point on nic: DHCP for IPv4,
// SLAAC for IPv6, everything else from DHCP.
func Defaults(nic string) Settings {
	return Settings{
		Management: Interface{Name: nic, IPv4: Family4{Mode: V4DHCP}, IPv6: Family6{Mode: V6SLAAC}},
		Cluster:    ClusterRanges{Pods: DefaultPods, Services: DefaultServices},
	}
}

// FieldError names the setting that failed validation.
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Reason }

// Field returns the field a NET_INVALID error names, or "".
func Field(err error) string {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func invalid(field, format string, args ...any) error {
	return codes.Wrap(codes.NetInvalid, &FieldError{Field: field, Reason: fmt.Sprintf(format, args...)})
}

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname reports whether name is a fully qualified host name of at
// least two labels.
func ValidHostname(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !label.MatchString(l) {
			return false
		}
	}
	return true
}

func validDomain(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if !label.MatchString(l) {
			return false
		}
	}
	return true
}

// Validate checks s against every rule of Section 2.2. The first failure is
// returned as NET_INVALID naming its field (Field reads it back).
func Validate(s Settings) error {
	if err := validateInterface("management", s.Management); err != nil {
		return err
	}
	if s.Management.IPv4.Mode == V4Off && s.Management.IPv6.Mode == V6Off {
		return invalid("management.ipv4", "turn on IPv4 or IPv6 for the management interface")
	}
	if s.Service != nil {
		if err := validateInterface("service", *s.Service); err != nil {
			return err
		}
		if s.Service.Name == s.Management.Name {
			return invalid("service.name", "the service interface must be a different NIC from the management interface")
		}
		if s.Service.IPv4.Mode == V4Off && s.Service.IPv6.Mode == V6Off {
			return invalid("service.ipv4", "turn on IPv4 or IPv6 for the service interface")
		}
	}
	if s.Hostname != "" && !ValidHostname(s.Hostname) {
		return invalid("hostname", "%q isn't a fully qualified host name, such as appliance.example.org", s.Hostname)
	}
	if len(s.DNS) > MaxDNS {
		return invalid("dns", "at most %d DNS servers", MaxDNS)
	}
	for i, a := range s.DNS {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return invalid(fmt.Sprintf("dns[%d]", i), "a DNS server must be an IPv4 or IPv6 address")
		}
	}
	if len(s.Search) > MaxSearch {
		return invalid("search", "at most %d search domains", MaxSearch)
	}
	for i, d := range s.Search {
		if !validDomain(d) {
			return invalid(fmt.Sprintf("search[%d]", i), "%q isn't a domain name", d)
		}
	}
	if len(s.NTP) > MaxNTP {
		return invalid("ntp", "at most %d NTP servers", MaxNTP)
	}
	for i, n := range s.NTP {
		if a, err := netip.ParseAddr(n); err == nil {
			if a.IsUnspecified() || a.IsMulticast() {
				return invalid(fmt.Sprintf("ntp[%d]", i), "%q can't be an NTP server", n)
			}
			continue
		}
		if !validDomain(n) {
			return invalid(fmt.Sprintf("ntp[%d]", i), "%q is neither an address nor a host name", n)
		}
	}
	if len(s.AllowList) > MaxAllowList {
		return invalid("allowList", "at most %d prefixes", MaxAllowList)
	}
	for i, p := range s.AllowList {
		if !p.IsValid() {
			return invalid(fmt.Sprintf("allowList[%d]", i), "not a prefix")
		}
		if p != p.Masked() {
			return invalid(fmt.Sprintf("allowList[%d]", i), "%s has host bits set; use %s", p, p.Masked())
		}
	}
	if s.TimeZone != "" {
		if _, err := time.LoadLocation(s.TimeZone); err != nil || s.TimeZone == "Local" {
			return invalid("timeZone", "%q isn't a time zone name, such as Europe/Paris or UTC", s.TimeZone)
		}
	}
	if s.HTTPSProxy != "" {
		u, err := url.Parse(s.HTTPSProxy)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return invalid("httpsProxy", "use an http:// or https:// proxy URL without credentials")
		}
	}
	return validateCluster(s)
}

func validateInterface(field string, i Interface) error {
	if i.Name == "" {
		return invalid(field+".name", "choose a network interface")
	}
	switch i.IPv4.Mode {
	case V4DHCP, V4Off:
		if i.IPv4.Address.IsValid() || i.IPv4.Gateway.IsValid() {
			return invalid(field+".ipv4.address", "an address is only set in static mode")
		}
	case V4Static:
		a := i.IPv4.Address
		if !a.IsValid() || !a.Addr().Is4() {
			return invalid(field+".ipv4.address", "give an IPv4 address with its prefix length, such as 192.0.2.10/24")
		}
		if !usableUnicast(a.Addr()) || isNetOrBroadcast(a) {
			return invalid(field+".ipv4.address", "%s isn't a usable host address", a)
		}
		if g := i.IPv4.Gateway; g.IsValid() && (!g.Is4() || !a.Masked().Contains(g) || g == a.Addr()) {
			return invalid(field+".ipv4.gateway", "the gateway must be another IPv4 address inside %s", a.Masked())
		}
	default:
		return invalid(field+".ipv4.mode", "use dhcp, static or off")
	}
	switch i.IPv6.Mode {
	case V6SLAAC, V6DHCPv6, V6Off:
		if i.IPv6.Address.IsValid() || i.IPv6.Gateway.IsValid() {
			return invalid(field+".ipv6.address", "an address is only set in static mode")
		}
	case V6Static:
		a := i.IPv6.Address
		if !a.IsValid() || !a.Addr().Is6() || a.Addr().Is4In6() {
			return invalid(field+".ipv6.address", "give an IPv6 address with its prefix length, such as 2001:db8::10/64")
		}
		if !usableUnicast(a.Addr()) || a.Addr().IsLinkLocalUnicast() {
			return invalid(field+".ipv6.address", "%s isn't a usable global or unique local address", a)
		}
		if g := i.IPv6.Gateway; g.IsValid() && (!g.Is6() || g == a.Addr() || !g.IsLinkLocalUnicast() && !a.Masked().Contains(g)) {
			return invalid(field+".ipv6.gateway", "the gateway must be a link-local address or another address inside %s", a.Masked())
		}
	default:
		return invalid(field+".ipv6.mode", "use slaac, dhcpv6, static or off")
	}
	return nil
}

// isNetOrBroadcast reports whether a's address is its subnet's network or
// broadcast address (only on /30 and wider; /31 and /32 have neither).
func isNetOrBroadcast(a netip.Prefix) bool {
	if a.Bits() > 30 {
		return false
	}
	net := a.Masked().Addr().As4()
	bcast := net
	hostBits := 32 - a.Bits()
	for i := 3; i >= 0 && hostBits > 0; i-- {
		n := min(hostBits, 8)
		bcast[i] |= 0xff >> (8 - n)
		hostBits -= n
	}
	return a.Addr() == netip.AddrFrom4(net) || a.Addr() == netip.AddrFrom4(bcast)
}

func usableUnicast(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalMulticast() &&
		a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

type namedPrefix struct {
	field string
	p     netip.Prefix
}

func validateCluster(s Settings) error {
	ranges := []namedPrefix{{"cluster.pods", s.Cluster.Pods}, {"cluster.services", s.Cluster.Services}}
	examples := map[string]netip.Prefix{"cluster.pods": DefaultPods, "cluster.services": DefaultServices}
	for _, r := range ranges {
		if !r.p.IsValid() {
			return invalid(r.field, "give a prefix, such as %s", examples[r.field])
		}
		if r.p != r.p.Masked() {
			return invalid(r.field, "%s has host bits set; use %s", r.p, r.p.Masked())
		}
	}
	if s.Cluster.Pods.Overlaps(s.Cluster.Services) {
		return invalid("cluster.services", "the pod and service ranges overlap")
	}
	var nets []namedPrefix
	for _, i := range []*Interface{&s.Management, s.Service} {
		if i == nil {
			continue
		}
		for _, a := range []netip.Prefix{i.IPv4.Address, i.IPv6.Address} {
			if a.IsValid() {
				nets = append(nets, namedPrefix{i.Name, a.Masked()})
			}
		}
	}
	for _, r := range ranges {
		if i := slices.IndexFunc(nets, func(n namedPrefix) bool { return n.p.Overlaps(r.p) }); i >= 0 {
			return invalid(r.field, "%s overlaps the network %s on %s", r.p, nets[i].p, nets[i].field)
		}
	}
	return nil
}
