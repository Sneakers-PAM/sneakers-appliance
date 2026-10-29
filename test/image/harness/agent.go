// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// AgentPort is the virtio-serial port name the QEMU guest agent listens
// on, the one Proxmox VE gives a VM with the agent on.
const AgentPort = "org.qemu.guest_agent.0"

// AgentReply is the guest agent's answer to one command: Return on
// success, Error when the agent refused or failed it.
type AgentReply struct {
	Return json.RawMessage `json:"return"`
	Error  *struct {
		Class string `json:"class"`
		Desc  string `json:"desc"`
	} `json:"error"`
}

// Agent runs execute on the guest agent (Options.GuestAgent) and returns
// its reply. It first syncs with guest-sync-delimited, as Proxmox VE does,
// so a reply left from an earlier try isn't taken for this one, and tries
// again until the agent answers or timeout passes.
func (vm *VM) Agent(execute string, timeout time.Duration) AgentReply {
	vm.t.Helper()
	if vm.agentSock == "" {
		vm.t.Fatal("Agent needs Options.GuestAgent")
	}
	deadline := time.Now().Add(timeout)
	var last error
	for id := time.Now().UnixNano(); time.Now().Before(deadline); id++ {
		if vm.exited() {
			vm.t.Fatalf("QEMU exited before the guest agent answered %s (last: %v)", execute, last)
		}
		r, err := vm.agentOnce(id, execute, true)
		if err == nil {
			return r
		}
		last = err
		time.Sleep(time.Second)
	}
	vm.t.Fatalf("the guest agent didn't answer %s in %s: %v", execute, timeout, last)
	return AgentReply{}
}

// AgentNoReply runs execute on the guest agent once it answers a sync,
// without waiting for a reply: guest-shutdown gives none when it works.
func (vm *VM) AgentNoReply(execute string, timeout time.Duration) {
	vm.t.Helper()
	if vm.agentSock == "" {
		vm.t.Fatal("AgentNoReply needs Options.GuestAgent")
	}
	deadline := time.Now().Add(timeout)
	var last error
	for id := time.Now().UnixNano(); time.Now().Before(deadline); id++ {
		_, err := vm.agentOnce(id, execute, false)
		if err == nil {
			return
		}
		last = err
		time.Sleep(time.Second)
	}
	vm.t.Fatalf("the guest agent didn't take %s in %s: %v", execute, timeout, last)
}

func (vm *VM) agentOnce(id int64, execute string, reply bool) (AgentReply, error) {
	c, err := net.DialTimeout("unix", vm.agentSock, 5*time.Second)
	if err != nil {
		return AgentReply{}, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(c)
	if _, err := fmt.Fprintf(c, "{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":%d}}\n", id); err != nil {
		return AgentReply{}, err
	}
	for {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			return AgentReply{}, fmt.Errorf("no sync reply: %w", err)
		}
		// The delimited sync puts 0xFF before its reply, to flush whatever
		// the guest had half-written.
		var sync struct {
			Return int64 `json:"return"`
		}
		if json.Unmarshal(bytes.TrimLeft(line, "\xff"), &sync) == nil && sync.Return == id {
			break
		}
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintf(c, "{\"execute\":%q}\n", execute); err != nil {
		return AgentReply{}, err
	}
	if !reply {
		return AgentReply{}, nil
	}
	line, err := rd.ReadBytes('\n')
	if err != nil {
		return AgentReply{}, fmt.Errorf("no reply to %s: %w", execute, err)
	}
	var r AgentReply
	if err := json.Unmarshal(line, &r); err != nil {
		return AgentReply{}, fmt.Errorf("reply to %s: %w: %q", execute, err, line)
	}
	if r.Return == nil && r.Error == nil {
		return AgentReply{}, errors.New("a reply with neither return nor error: " + string(line))
	}
	return r, nil
}
