// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"
	"net/netip"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
)

var (
	v4ToWire = map[Mode4]netdv1.Ipv4Mode{V4DHCP: netdv1.Ipv4Mode_IPV4_MODE_DHCP, V4Static: netdv1.Ipv4Mode_IPV4_MODE_STATIC, V4Off: netdv1.Ipv4Mode_IPV4_MODE_OFF}
	v6ToWire = map[Mode6]netdv1.Ipv6Mode{V6SLAAC: netdv1.Ipv6Mode_IPV6_MODE_SLAAC, V6DHCPv6: netdv1.Ipv6Mode_IPV6_MODE_DHCPV6, V6Static: netdv1.Ipv6Mode_IPV6_MODE_STATIC, V6Off: netdv1.Ipv6Mode_IPV6_MODE_OFF}
)

// ToWire converts s to its proto form.
func ToWire(s Settings) *netdv1.Settings {
	w := &netdv1.Settings{
		Management: ifaceToWire(s.Management),
		Hostname:   s.Hostname,
		Search:     s.Search,
		Ntp:        s.NTP,
		TimeZone:   s.TimeZone,
		HttpsProxy: s.HTTPSProxy,
		Cluster:    &netdv1.ClusterRanges{Pods: prefixString(s.Cluster.Pods), Services: prefixString(s.Cluster.Services)},
	}
	if s.Service != nil {
		w.Service = ifaceToWire(*s.Service)
	}
	for _, a := range s.DNS {
		w.Dns = append(w.Dns, a.String())
	}
	for _, p := range s.AllowList {
		w.AllowList = append(w.AllowList, p.String())
	}
	return w
}

// FromWire parses the proto form; a value that doesn't parse is NET_INVALID
// naming its field. The result isn't validated: Set runs Validate.
func FromWire(w *netdv1.Settings) (Settings, error) {
	if w == nil {
		return Settings{}, invalid("settings", "no settings given")
	}
	s := Settings{Hostname: w.GetHostname(), Search: w.GetSearch(), NTP: w.GetNtp(), TimeZone: w.GetTimeZone(), HTTPSProxy: w.GetHttpsProxy()}
	var err error
	if s.Management, err = ifaceFromWire("management", w.GetManagement()); err != nil {
		return Settings{}, err
	}
	if w.Service != nil {
		svc, err := ifaceFromWire("service", w.GetService())
		if err != nil {
			return Settings{}, err
		}
		s.Service = &svc
	}
	for i, d := range w.GetDns() {
		a, err := netip.ParseAddr(d)
		if err != nil {
			return Settings{}, invalid(fmt.Sprintf("dns[%d]", i), "%q isn't an address", d)
		}
		s.DNS = append(s.DNS, a)
	}
	for i, p := range w.GetAllowList() {
		pp, err := netip.ParsePrefix(p)
		if err != nil {
			return Settings{}, invalid(fmt.Sprintf("allowList[%d]", i), "%q isn't a prefix such as 192.0.2.0/24", p)
		}
		s.AllowList = append(s.AllowList, pp)
	}
	if s.Cluster.Pods, err = parsePrefix("cluster.pods", w.GetCluster().GetPods()); err != nil {
		return Settings{}, err
	}
	if s.Cluster.Services, err = parsePrefix("cluster.services", w.GetCluster().GetServices()); err != nil {
		return Settings{}, err
	}
	return s, nil
}

func ifaceToWire(i Interface) *netdv1.Interface {
	return &netdv1.Interface{
		Name: i.Name,
		Ipv4: &netdv1.Ipv4{Mode: v4ToWire[i.IPv4.Mode], Address: prefixString(i.IPv4.Address), Gateway: addrString(i.IPv4.Gateway)},
		Ipv6: &netdv1.Ipv6{Mode: v6ToWire[i.IPv6.Mode], Address: prefixString(i.IPv6.Address), Gateway: addrString(i.IPv6.Gateway)},
	}
}

func ifaceFromWire(field string, w *netdv1.Interface) (Interface, error) {
	i := Interface{Name: w.GetName()}
	for m, wm := range v4ToWire {
		if wm == w.GetIpv4().GetMode() {
			i.IPv4.Mode = m
		}
	}
	for m, wm := range v6ToWire {
		if wm == w.GetIpv6().GetMode() {
			i.IPv6.Mode = m
		}
	}
	var err error
	if i.IPv4.Address, err = parsePrefix(field+".ipv4.address", w.GetIpv4().GetAddress()); err != nil {
		return Interface{}, err
	}
	if i.IPv4.Gateway, err = parseAddr(field+".ipv4.gateway", w.GetIpv4().GetGateway()); err != nil {
		return Interface{}, err
	}
	if i.IPv6.Address, err = parsePrefix(field+".ipv6.address", w.GetIpv6().GetAddress()); err != nil {
		return Interface{}, err
	}
	if i.IPv6.Gateway, err = parseAddr(field+".ipv6.gateway", w.GetIpv6().GetGateway()); err != nil {
		return Interface{}, err
	}
	return i, nil
}

func parsePrefix(field, s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, invalid(field, "%q isn't an address with its prefix length", s)
	}
	return p, nil
}

func parseAddr(field, s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, invalid(field, "%q isn't an address", s)
	}
	return a, nil
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
