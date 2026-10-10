// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"fmt"
	"strings"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Key is one key=value setting a command takes. The command's help, its
// key list and its parser all read the same table.
type Key struct {
	Name, Help, Example string
	set                 func(st *netdv1.Settings, v string)
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

// parseKeys checks each word is key=value with a key from keys, and
// returns them in order. cmd names the command in the errors.
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
