// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const withPhases = `format: 2
switches:
  - name: mcp
    label: The MCP server
    stacks: [app-mcp]
phases:
  - name: data
    label: Starting the database
    stack: app-data
    workloads: [app-postgres, app-valkey]
    timeout: 3m
  - name: front
    label: Starting the web apps
    stack: app-front
    workloads: [app-gateway]
    switch_stacks: [app-mcp]
`

// A product's phases parse in order, each with its own stack, its
// workloads, the switch stacks placed with it and its timeout (5 minutes
// when it names none).
func TestThePhasesParse(t *testing.T) {
	s, err := productspec.Parse([]byte(withPhases))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Phases) != 2 || s.Phases[0].Name != "data" || s.Phases[1].Stack != "app-front" {
		t.Fatalf("%+v", s.Phases)
	}
	if s.Phases[0].TimeoutOrDefault() != 3*time.Minute || s.Phases[1].TimeoutOrDefault() != productspec.DefaultPhaseTimeout {
		t.Fatalf("timeouts %v %v", s.Phases[0].TimeoutOrDefault(), s.Phases[1].TimeoutOrDefault())
	}
	if got := s.PhaseStacks(); !slices.Equal(got, []string{"app-data", "app-mcp", "app-front"}) {
		t.Fatalf("phase stacks %v", got)
	}
	if got := s.Phases[1].Stacks(); !slices.Equal(got, []string{"app-mcp", "app-front"}) {
		t.Fatalf("the front phase's stacks %v", got)
	}
	if i, ok := s.PhaseOf("app-postgres"); !ok || i != 0 {
		t.Fatalf("app-postgres in %d %v", i, ok)
	}
	if _, ok := s.PhaseOf("app-other"); ok {
		t.Fatal("a workload no phase names has a phase")
	}
	if none, _ := productspec.Parse([]byte("format: 2\n")); len(none.Phases) != 0 || len(none.PhaseStacks()) != 0 {
		t.Fatal("no phases section declares no phases")
	}
}

func TestAPhaseIsRefusedWhenItBreaksARule(t *testing.T) {
	head := "format: 2\nswitches:\n  - {name: mcp, stacks: [app-mcp]}\n  - {name: import, stacks: [app-import]}\nphases:\n"
	for name, doc := range map[string]string{
		"a bad name":               "  - {name: Data, label: x, stack: app-data, workloads: [a]}\n",
		"a name twice":             "  - {name: data, label: x, stack: app-a, workloads: [a]}\n  - {name: data, label: x, stack: app-b, workloads: [b]}\n",
		"no label":                 "  - {name: data, stack: app-data, workloads: [a]}\n",
		"no stack":                 "  - {name: data, label: x, workloads: [a]}\n",
		"a stack twice":            "  - {name: a, label: x, stack: app-a, workloads: [a]}\n  - {name: b, label: x, stack: app-a, workloads: [b]}\n",
		"a switch's stack as own":  "  - {name: a, label: x, stack: app-mcp, workloads: [a]}\n",
		"the appliance's stack":    "  - {name: a, label: x, stack: sneakers-appliance-secrets, workloads: [a]}\n",
		"no workloads":             "  - {name: a, label: x, stack: app-a}\n",
		"a bad workload":           "  - {name: a, label: x, stack: app-a, workloads: [App_A]}\n",
		"a workload twice":         "  - {name: a, label: x, stack: app-a, workloads: [w]}\n  - {name: b, label: x, stack: app-b, workloads: [w]}\n",
		"an undeclared switch":     "  - {name: a, label: x, stack: app-a, workloads: [a], switch_stacks: [app-nope]}\n",
		"a switch stack twice":     "  - {name: a, label: x, stack: app-a, workloads: [a], switch_stacks: [app-mcp]}\n  - {name: b, label: x, stack: app-b, workloads: [b], switch_stacks: [app-mcp]}\n",
		"a short timeout":          "  - {name: a, label: x, stack: app-a, workloads: [a], timeout: 10s}\n",
		"a long timeout":           "  - {name: a, label: x, stack: app-a, workloads: [a], timeout: 2h}\n",
		"a timeout that isn't one": "  - {name: a, label: x, stack: app-a, workloads: [a], timeout: soon}\n",
	} {
		if _, err := productspec.Parse([]byte(head + doc)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The import's stack is placed by the Import page, never by a phase.
func TestTheImportStackIsNeverAPhaseStack(t *testing.T) {
	doc := withImport + "phases:\n  - {name: a, label: x, stack: app-a, workloads: [a], switch_stacks: [sneakers-import]}\n"
	if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("the import stack as a phase's switch stack: %v", err)
	}
}

// A slot records its phase stacks in order, "<order> <phase> <stack>",
// for k0s-interim, which leaves them to the box's phase loop; a slot
// without phases has no such file.
func TestThePhaseStacksAreWrittenIntoTheSlot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, productspec.File), []byte(withPhases), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, productspec.PhaseStacksFile))
	if err != nil || string(b) != "1 data app-data\n2 front app-mcp\n2 front app-front\n" {
		t.Fatalf("%q %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(dir, productspec.File), []byte("format: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, productspec.PhaseStacksFile)); !os.IsNotExist(err) {
		t.Fatalf("a slot without phases keeps a phase stacks file: %v", err)
	}
}

// The Sneakers bundle names every workload it renders in a phase, in the
// order the product needs them: data, then sign-in and the vault, then
// the services, then the gateway and the web apps with the MCP.
func TestTheSneakersBundleDeclaresItsPhases(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range s.Phases {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"data", "identity", "services", "front"}) {
		t.Fatalf("phases %v", names)
	}
	want := map[string]int{
		"sneakers-postgres": 0, "sneakers-valkey": 0,
		"sneakers-kratos": 1, "sneakers-identity": 1, "sneakers-vault": 1,
		"sneakers-workflow": 2, "sneakers-audit": 2, "sneakers-notify": 2, "sneakers-connector": 2, "sneakers-sshbroker": 2,
		"sneakers-gateway": 3, "sneakers-web-staff": 3, "sneakers-web-admin": 3, "sneakers-mcp": 3, "sneakers-hydra": 3,
	}
	for w, i := range want {
		if got, ok := s.PhaseOf(w); !ok || got != i {
			t.Errorf("%s: phase %d %v, want %d", w, got, ok, i)
		}
	}
	if !slices.Contains(s.Phases[3].SwitchStacks, "sneakers-mcp") {
		t.Errorf("the front phase places the MCP switch's stack: %v", s.Phases[3].SwitchStacks)
	}
}

// An import holds the product after the phase import.after names: what
// the import writes to runs, and nothing past it (no sign-in, no agent)
// until it's closed. It must name a phase.
func TestTheImportHoldsAfterAPhase(t *testing.T) {
	doc := withImport + "phases:\n  - {name: data, label: x, stack: app-data, workloads: [a]}\n  - {name: front, label: y, stack: app-front, workloads: [b]}\n"
	s, err := productspec.Parse([]byte(strings.Replace(doc, "import:\n", "import:\n  after: data\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Import.After != "data" {
		t.Fatalf("after %q", s.Import.After)
	}
	if _, err := productspec.Parse([]byte(strings.Replace(doc, "import:\n", "import:\n  after: nope\n", 1))); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("an after that names no phase: %v", err)
	}
	if _, err := productspec.Parse([]byte(strings.Replace(withImport, "import:\n", "import:\n  after: data\n", 1))); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("an after without phases: %v", err)
	}
}

// The Sneakers import holds the product after the services phase: the
// import writes to the vault and the audit service, and the gateway and
// the web apps (sign-in, MCP) stay down until it's closed.
func TestTheSneakersImportHoldsAfterTheServices(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if s.Import == nil || s.Import.After != "services" {
		t.Fatalf("%+v", s.Import)
	}
}
