// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netdapi_test

import (
	"fmt"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
)

func TestBindable(t *testing.T) {
	got := fmt.Sprint(netdapi.Bindable([]string{"192.0.2.10/24", "2001:db8::10", "fe80::1/64", "not an address"}))
	if got != "[192.0.2.10 2001:db8::10]" {
		t.Fatalf("bindable %s", got)
	}
}
