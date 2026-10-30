// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"fmt"
	"net/netip"
	"strings"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Key is one key=value setting a command takes. The command's help, its
// key list and its parser all read the same table.
type Key struct {
	Name, Help, Example string
	set                 func(st *netdv1.Settings, v string)
	check               func(v string) error
}

// list is a comma-separated value; empty clears it.
func list(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

var networkKeys = []Key{
	{Name: "hostname", Help: "the box's host name", Example: "hostname=box1.sneakers.example.org",
		set: func(st *netdv1.Settings, v string) { st.Hostname = v }},
	{Name: "dns", Help: "the DNS servers, comma-separated; empty clears them", Example: "dns=192.0.2.53,192.0.2.54",
		set: func(st *netdv1.Settings, v string) { st.Dns = list(v) }},
	{Name: "search", Help: "the DNS search domains, comma-separated", Example: "search=sneakers.example.org",
		set: func(st *netdv1.Settings, v string) { st.Search = list(v) }},
	{Name: "ntp", Help: "the NTP servers, comma-separated", Example: "ntp=192.0.2.123,time.example.org",
		set: func(st *netdv1.Settings, v string) { st.Ntp = list(v) }},
	{Name: "allow-list", Help: "the networks that may reach SSH and :8443, comma-separated CIDRs", Example: "allow-list=192.0.2.0/24,198.51.100.0/24",
		set: func(st *netdv1.Settings, v string) { st.AllowList = list(v) }},
	{Name: "time-zone", Help: "the time zone the box shows times in, an IANA name", Example: "time-zone=America/New_York",
		set: func(st *netdv1.Settings, v string) { st.TimeZone = v }},
	{Name: "https-proxy", Help: "the proxy for outbound HTTPS, a URL; empty for none", Example: "https-proxy=http://192.0.2.8:3128",
		set: func(st *netdv1.Settings, v string) { st.HttpsProxy = v }},
	{Name: "ipv4", Help: "the management interface's IPv4 mode: dhcp, static or off", Example: "ipv4=static",
		set: func(st *netdv1.Settings, v string) { management(st).Ipv4.Mode = ipv4Mode(v) }, check: checkIPv4Mode},
	{Name: "ipv4-address", Help: "the IPv4 address and its prefix length, in static mode; empty clears it", Example: "ipv4-address=192.0.2.10/24",
		set: func(st *netdv1.Settings, v string) { management(st).Ipv4.Address = v }},
	{Name: "ipv4-gateway", Help: "the IPv4 gateway, in static mode; empty for none", Example: "ipv4-gateway=192.0.2.1",
		set: func(st *netdv1.Settings, v string) { management(st).Ipv4.Gateway = v }},
	{Name: "ipv6", Help: "the management interface's IPv6 mode: slaac, dhcpv6, static or off", Example: "ipv6=static",
		set: func(st *netdv1.Settings, v string) { management(st).Ipv6.Mode = ipv6Mode(v) }, check: checkIPv6Mode},
	{Name: "ipv6-address", Help: "the IPv6 address and its prefix length, in static mode; empty clears it", Example: "ipv6-address=2001:db8::10/64",
		set: func(st *netdv1.Settings, v string) { management(st).Ipv6.Address = v }},
	{Name: "ipv6-gateway", Help: "the IPv6 gateway, in static mode; empty for none", Example: "ipv6-gateway=2001:db8::1",
		set: func(st *netdv1.Settings, v string) { management(st).Ipv6.Gateway = v }},
}

// management is st's management interface, with its IPv4 and IPv6 blocks,
// created if netd gave none yet (a box has one by the time setup finishes).
// The mode and address keys apply in the same network set, so a half-typed
// one (an address with no ipv4=static) is caught by netd's own validation,
// the same way an invalid address is.
func management(st *netdv1.Settings) *netdv1.Interface {
	if st.Management == nil {
		st.Management = &netdv1.Interface{}
	}
	if st.Management.Ipv4 == nil {
		st.Management.Ipv4 = &netdv1.Ipv4{}
	}
	if st.Management.Ipv6 == nil {
		st.Management.Ipv6 = &netdv1.Ipv6{}
	}
	return st.Management
}

func checkIPv4Mode(v string) error {
	return checkMode("ipv4", "dhcp, static or off", v, ipv4Mode(v) != netdv1.Ipv4Mode_IPV4_MODE_UNSPECIFIED,
		netip.Addr.Is4, "ipv4=static ipv4-address=192.0.2.10/24 ipv4-gateway=192.0.2.1")
}

func checkIPv6Mode(v string) error {
	return checkMode("ipv6", "slaac, dhcpv6, static or off", v, ipv6Mode(v) != netdv1.Ipv6Mode_IPV6_MODE_UNSPECIFIED,
		netip.Addr.Is6, "ipv6=static ipv6-address=2001:db8::10/64 ipv6-gateway=2001:db8::1")
}

// checkMode refuses a mode that isn't one of modes. An address of the
// key's own family is the natural mistake, so it says where that goes.
// Only the part before the slash decides: a bad prefix length still means
// an address, and netd judges it once it's in the right key.
func checkMode(key, modes, v string, valid bool, family func(netip.Addr) bool, example string) error {
	if valid {
		return nil
	}
	host, _, _ := strings.Cut(v, "/")
	if a, err := netip.ParseAddr(host); err == nil && family(a) {
		return codes.New(codes.ShellParse, "%q takes %s; put the address in %s-address= (for example: network set %s)", key, modes, key, example)
	}
	return codes.New(codes.ShellParse, "%q takes %s, not %q (help network set lists the keys)", key, modes, Printable(v))
}

// ipv4Mode and ipv6Mode parse the key's value; checkIPv4Mode and
// checkIPv6Mode have already refused anything unrecognized.
func ipv4Mode(v string) netdv1.Ipv4Mode {
	switch v {
	case "dhcp":
		return netdv1.Ipv4Mode_IPV4_MODE_DHCP
	case "static":
		return netdv1.Ipv4Mode_IPV4_MODE_STATIC
	case "off":
		return netdv1.Ipv4Mode_IPV4_MODE_OFF
	default:
		return netdv1.Ipv4Mode_IPV4_MODE_UNSPECIFIED
	}
}

func ipv6Mode(v string) netdv1.Ipv6Mode {
	switch v {
	case "slaac":
		return netdv1.Ipv6Mode_IPV6_MODE_SLAAC
	case "dhcpv6":
		return netdv1.Ipv6Mode_IPV6_MODE_DHCPV6
	case "static":
		return netdv1.Ipv6Mode_IPV6_MODE_STATIC
	case "off":
		return netdv1.Ipv6Mode_IPV6_MODE_OFF
	default:
		return netdv1.Ipv6Mode_IPV6_MODE_UNSPECIFIED
	}
}

// NetworkKeys are the keys network set takes.
func NetworkKeys() []Key { return networkKeys }

// keyList is the help's list of keys: one line each with an example.
func keyList(keys []Key) string {
	var b strings.Builder
	w := 0
	for _, k := range keys {
		w = max(w, len(k.Name))
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-*s  %s\n  %-*s  e.g. %s\n", w+1, k.Name+"=", k.Help, w+1, "", k.Example)
	}
	return b.String()
}

func keyData(keys []Key) []map[string]string {
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]string{"key": k.Name, "help": k.Help, "example": k.Example})
	}
	return out
}

// parseKeys checks each word is key=value with a key from keys and a value
// the key's own check accepts, and returns them in order. cmd names the
// command in the errors.
func parseKeys(cmd string, keys []Key, words []string) ([]keyValue, error) {
	out := make([]keyValue, 0, len(words))
	for _, w := range words {
		name, v, ok := strings.Cut(w, "=")
		k, found := findKey(keys, name)
		switch {
		case !ok && found:
			return nil, codes.New(codes.ShellParse, "%q isn't key=value; did you mean %s=<value>? (help %s lists the keys)", Printable(w), k.Name, cmd)
		case !ok:
			return nil, codes.New(codes.ShellParse, "%q isn't key=value%s (help %s lists the keys)", Printable(w), suggest(keys, name), cmd)
		case !found:
			return nil, codes.New(codes.ShellParse, "%q isn't a key %s takes%s (help %s lists the keys)", Printable(name), cmd, suggest(keys, name), cmd)
		}
		if k.check != nil {
			if err := k.check(v); err != nil {
				return nil, err
			}
		}
		out = append(out, keyValue{k, v})
	}
	return out, nil
}

type keyValue struct {
	key   Key
	value string
}

func findKey(keys []Key, name string) (Key, bool) {
	for _, k := range keys {
		if k.Name == name {
			return k, true
		}
	}
	return Key{}, false
}

// suggest is "; did you mean <key>?" for the key closest to name, or
// nothing when none is close.
func suggest(keys []Key, name string) string {
	best, bestD := "", 0
	for _, k := range keys {
		d := distance(strings.ToLower(name), k.Name)
		if best == "" || d < bestD {
			best, bestD = k.Name, d
		}
	}
	if best == "" || bestD > max(1, len(best)/3) {
		return ""
	}
	return "; did you mean " + best + "?"
}

// distance is the edit distance between a and b.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
