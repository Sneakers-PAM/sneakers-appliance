// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Support is one section a product adds to the box's support bundle
// (docs/support-bundle.md): one command, or one kubectl read. Nothing here
// reaches a shell, and the check below refuses anything that isn't
// read-only, bounded and built into the box's busybox, so a product can
// add to a bundle and can't turn it against the box.
type Support struct {
	// Title names the section, under the bundle's "Product: <name>".
	Title string `yaml:"title"`
	// Command is a busybox applet and its options, split on spaces.
	Command string `yaml:"command"`
	// Kubectl is a read of the cluster.
	Kubectl *SupportKubectl `yaml:"kubectl"`
	// Timeout bounds the section, a duration such as "20s" up to
	// MaxSupportTimeout; empty is DefaultSupportTimeout.
	Timeout string `yaml:"timeout"`
	// Redact are more patterns (RE2) to mask in this section's output.
	// They add to the base's redaction and can't turn any of it off.
	Redact []string `yaml:"redact"`
	// Short puts the section in the short form too; every section is in
	// the full form.
	Short bool `yaml:"short"`
}

// SupportKubectl is a kubectl read, by its parts so nothing else can be
// asked: get prints a table, describe a resource's description, and logs
// the logs of the pods Selector picks.
type SupportKubectl struct {
	Verb string `yaml:"verb"`
	// Resource is one of supportResources; logs has none.
	Resource string `yaml:"resource"`
	// Namespace is required for describe and logs; get without one reads
	// every namespace.
	Namespace string `yaml:"namespace"`
	// Selector is a label selector, required for logs.
	Selector string `yaml:"selector"`
	// Previous reads the previous container's logs.
	Previous bool `yaml:"previous"`
	// Tail is how many lines of each container's log, up to
	// MaxSupportTail; 0 is the form's own (50 short, 2000 full).
	Tail int `yaml:"tail"`
}

// The bounds of a section.
const (
	DefaultSupportTimeout = 15 * time.Second
	MaxSupportTimeout     = 60 * time.Second
	MaxSupportTail        = 5000
	MaxSupportSections    = 32
)

// appletRule is what one busybox applet may be given in a product's
// section. Every applet here reads and prints; none can write.
type appletRule struct {
	// flags are the options it may take; valued flags take one number.
	flags  []string
	valued []string
	// paths says it takes paths, each under DataRoot; without it, no
	// operand is allowed.
	paths bool
}

var supportApplets = map[string]appletRule{
	"cat":    {paths: true},
	"df":     {flags: []string{"-h", "-k"}, paths: true},
	"du":     {flags: []string{"-s", "-h", "-k"}, paths: true},
	"free":   {flags: []string{"-m"}},
	"head":   {valued: []string{"-n"}, paths: true},
	"ls":     {flags: []string{"-l", "-a", "-h", "--full-time"}, paths: true},
	"tail":   {valued: []string{"-n"}, paths: true},
	"uptime": {},
	"wc":     {flags: []string{"-l", "-c"}, paths: true},
}

// SupportApplets are the applets a product's section may run and each
// one's options, for the test that holds them to the box's busybox config.
func SupportApplets() map[string][]string {
	out := map[string][]string{}
	for name, r := range supportApplets {
		out[name] = slices.Concat(r.flags, r.valued)
	}
	return out
}

// supportResources are the resources a section may read: none of them
// carries a value a product keeps secret. Secrets and ConfigMaps aren't
// here; the base lists Secrets by name itself.
var supportResources = []string{
	"certificates.cert-manager.io", "cronjobs", "daemonsets", "deployments", "endpoints", "events", // scrub:allow=fqdn -- a Kubernetes API group
	"ingresses", "ingressroutes.traefik.io", "jobs", "networkpolicies", "nodes", "persistentvolumeclaims", // scrub:allow=fqdn -- a Kubernetes API group
	"persistentvolumes", "pods", "replicasets", "services", "statefulsets",
}

var (
	supportWordRE     = regexp.MustCompile(`^[A-Za-z0-9_./:=,%+\-]+$`)
	supportNamespace  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	supportSelectorRE = regexp.MustCompile(`^[A-Za-z0-9._/\-]+(!?=[A-Za-z0-9._\-]*)?(,[A-Za-z0-9._/\-]+(!?=[A-Za-z0-9._\-]*)?)*$`)
	supportNumber     = regexp.MustCompile(`^[0-9]{1,6}$`)
)

func (s Spec) checkSupport() error {
	if len(s.Support) > MaxSupportSections {
		return bad("support: %d sections; a product may declare %d", len(s.Support), MaxSupportSections)
	}
	seen := map[string]bool{}
	for i, c := range s.Support {
		if err := c.check(); err != nil {
			return bad("support[%d]: %v", i, err)
		}
		if seen[c.Title] {
			return bad("support[%d]: %q is declared twice", i, c.Title)
		}
		seen[c.Title] = true
	}
	return nil
}

func (c Support) check() error {
	if strings.TrimSpace(c.Title) == "" || strings.ContainsAny(c.Title, "\r\n\t") {
		return bad("a section has a one-line title")
	}
	if (c.Command == "") == (c.Kubectl == nil) {
		return bad("%s: a section has a command or a kubectl read, not both", c.Title)
	}
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 || d > MaxSupportTimeout {
			return bad("%s: the timeout %q isn't a duration up to %s", c.Title, c.Timeout, MaxSupportTimeout)
		}
	}
	for _, p := range c.Redact {
		if p == "" {
			return bad("%s: an empty redact pattern", c.Title)
		}
		if _, err := regexp.Compile(p); err != nil {
			return bad("%s: the redact pattern %q doesn't compile: %v", c.Title, p, err)
		}
	}
	if c.Kubectl != nil {
		return c.Kubectl.check(c.Title)
	}
	return checkSupportCommand(c.Title, c.Command)
}

func (k SupportKubectl) check(title string) error {
	if k.Namespace != "" && !supportNamespace.MatchString(k.Namespace) {
		return bad("%s: %q isn't a namespace", title, k.Namespace)
	}
	if k.Selector != "" && !supportSelectorRE.MatchString(k.Selector) {
		return bad("%s: %q isn't a label selector", title, k.Selector)
	}
	if k.Tail < 0 || k.Tail > MaxSupportTail {
		return bad("%s: tail %d isn't between 0 and %d", title, k.Tail, MaxSupportTail)
	}
	switch k.Verb {
	case "get", "describe":
		if !slices.Contains(supportResources, k.Resource) {
			return bad("%s: %q isn't a resource a section may read", title, k.Resource)
		}
		if k.Previous || k.Tail != 0 {
			return bad("%s: previous and tail are for logs", title)
		}
		if k.Verb == "describe" && k.Namespace == "" {
			return bad("%s: describe needs a namespace", title)
		}
	case "logs":
		if k.Resource != "" {
			return bad("%s: logs reads pods by a selector, not a resource", title)
		}
		if k.Namespace == "" || k.Selector == "" {
			return bad("%s: logs needs a namespace and a selector", title)
		}
	default:
		return bad("%s: %q isn't a read a section may make (get, describe or logs)", title, k.Verb)
	}
	return nil
}

func checkSupportCommand(title, command string) error {
	words := strings.Fields(command)
	if len(words) == 0 {
		return bad("%s: the command is empty", title)
	}
	rule, ok := supportApplets[words[0]]
	if !ok {
		return bad("%s: %q isn't an applet a section may run", title, words[0])
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		if !supportWordRE.MatchString(w) {
			return bad("%s: %q has a character a section may not use", title, w)
		}
		switch {
		case slices.Contains(rule.valued, w):
			i++
			if i == len(words) || !supportNumber.MatchString(words[i]) {
				return bad("%s: %s %s takes a number", title, words[0], w)
			}
		case strings.HasPrefix(w, "-"):
			if !slices.Contains(rule.flags, w) {
				return bad("%s: %s doesn't take %s here (one option a word)", title, words[0], w)
			}
		case !rule.paths:
			return bad("%s: %s takes no operand here", title, words[0])
		case !underDataRoot(w):
			return bad("%s: %q isn't a clean path under %s", title, w, DataRoot)
		}
	}
	return nil
}

func underDataRoot(p string) bool {
	return path.Clean(p) == p && (p == DataRoot || strings.HasPrefix(p, DataRoot+"/"))
}

// Deadline is how long the section may run.
func (c Support) Deadline() time.Duration {
	if d, err := time.ParseDuration(c.Timeout); err == nil && d > 0 {
		return d
	}
	return DefaultSupportTimeout
}

// Words are the busybox applet and its arguments.
func (c Support) Words() []string { return strings.Fields(c.Command) }

// Args are kubectl's arguments, with tail lines of each log when the
// section names none.
func (k SupportKubectl) Args(tail int) []string {
	var args []string
	switch k.Verb {
	case "logs":
		if k.Tail != 0 {
			tail = k.Tail
		}
		args = []string{"logs", "-n", k.Namespace, "-l", k.Selector, "--all-containers", "--prefix", "--timestamps", "--tail=" + strconv.Itoa(tail)}
		if k.Previous {
			args = append(args, "--previous")
		}
		return args
	case "describe":
		args = []string{"describe", k.Resource, "-n", k.Namespace}
	default:
		args = []string{"get", k.Resource}
		if k.Namespace == "" {
			args = append(args, "-A")
		} else {
			args = append(args, "-n", k.Namespace)
		}
		args = append(args, "-o", "wide")
	}
	if k.Selector != "" {
		args = append(args, "-l", k.Selector)
	}
	return args
}
