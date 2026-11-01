// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"testing"
	"time"
)

func TestAnExportTicketWorksOnceForItsOwnerInTime(t *testing.T) {
	var x exportTickets
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	id, err := x.issue("s1", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := x.take(id, "bob", now); ok {
		t.Fatal("another admin used the ticket")
	}
	id, err = x.issue("s1", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if set, ok := x.take(id, "alice", now.Add(time.Second)); !ok || set != "s1" {
		t.Fatalf("got %q, %v", set, ok)
	}
	if _, ok := x.take(id, "alice", now.Add(time.Second)); ok {
		t.Fatal("a ticket worked twice")
	}
	id, err = x.issue("s1", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := x.take(id, "alice", now.Add(exportTicketLife+time.Second)); ok {
		t.Fatal("a stale ticket worked")
	}
}
