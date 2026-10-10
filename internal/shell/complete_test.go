// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"slices"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

func completeAs(role, typed string) (string, []string) {
	e := &shell.Env{Origin: shell.OriginSSH, Backend: &recordingBackend{}, Product: sneakers, Role: role}
	return shell.Completions(e, typed)
}

// Tab completes commands, subcommands, flags and the values the shell
// knows, through the command tree's own completion.
func TestTabCompletesCommandsFlagsAndValues(t *testing.T) {
	for typed, want := range map[string]string{
		"snea":                                "sneakers ",
		"sneakers m":                          "sneakers mcp ",
		"sneakers mcp of":                     "sneakers mcp off ",
		"sneakers mcp on m":                   "sneakers mcp on machine-api=",
		"sneakers mcp on machine-api=of":      "sneakers mcp on machine-api=off ",
		"network set ti":                      "network set time-zone=",
		"network set time-zone=America/New_Y": "network set time-zone=America/New_York ",
		"network set time-zone=Europe/Pa":     "network set time-zone=Europe/Paris ",
		"network set hostname=x d":            "network set hostname=x dns=",
		"keys list --a":                       "keys list --admin ",
		"status --output j":                   "status --output json ",
		"help network s":                      "help network s",
		"zzz":                                 "zzz",
	} {
		if got, _ := completeAs("owner", typed); got != want {
			t.Errorf("%q completes to %q, want %q", typed, got, want)
		}
	}
	_, options := completeAs("owner", "sneakers mcp ")
	if !slices.Equal(options, []string{"off", "on"}) {
		t.Errorf("mcp options %v", options)
	}
	_, options = completeAs("owner", "network set time-zone=America/New_")
	if !slices.Contains(options, "time-zone=America/New_York") {
		t.Errorf("time zone options %v", options)
	}
	_, options = completeAs("owner", "network set hostname=x ")
	if slices.Contains(options, "hostname=") || !slices.Contains(options, "dns=") {
		t.Errorf("a key already given is offered again: %v", options)
	}
}

// Only the commands the login's role may run are offered: an admin who
// isn't an owner isn't offered network set or network confirm.
func TestTabIsRoleAware(t *testing.T) {
	if got, _ := completeAs("admin", "network s"); got != "network show " {
		t.Errorf("an admin completes %q", got)
	}
	_, options := completeAs("admin", "network ")
	if slices.Contains(options, "set") || slices.Contains(options, "confirm") || !slices.Contains(options, "show") {
		t.Errorf("an admin is offered %v", options)
	}
	_, options = completeAs("owner", "network ")
	if !slices.Contains(options, "set") || !slices.Contains(options, "confirm") {
		t.Errorf("an owner is offered %v", options)
	}
}
