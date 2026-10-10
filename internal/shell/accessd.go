// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// UseAccessd points the accessd clients (the local API and the sign-in
// approval) at baseURL through hc.
func (s *Services) UseAccessd(hc connect.HTTPClient, baseURL string) {
	opt := connect.WithInterceptors(s.identify())
	s.Access = accessv1connect.NewAccessServiceClient(hc, baseURL, opt)
	s.Network = accessv1connect.NewNetworkServiceClient(hc, baseURL, opt)
	s.Setup = accessv1connect.NewSetupServiceClient(hc, baseURL, opt)
	s.Elevation = accessv1connect.NewElevationServiceClient(hc, baseURL, opt)
	s.SSHLogin = accessv1connect.NewSshLoginServiceClient(hc, baseURL, opt)
	s.Local = osadminv1connect.NewLocalServiceClient(hc, baseURL)
}

// identify sends the login's key and SSH client address with each call,
// for accessd's audit entry; accessd takes the identity from the uid.
func (s *Services) identify() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			if s.Session.KeyFingerprint != "" {
				r.Header().Set(accessapi.KeyHeader, s.Session.KeyFingerprint)
			}
			if s.Session.Source != "" {
				r.Header().Set(accessapi.SourceHeader, s.Session.Source)
			}
			return next(ctx, r)
		}
	}
}

// accessd carries out an accessd command; ok is false for an action that
// isn't accessd's.
func (s *Services) accessd(ctx context.Context, r Request) (Result, bool, error) {
	if s.Access == nil {
		if r.Action == "status" {
			res, err := s.cachedStatus()
			return res, true, err
		}
		switch r.Action {
		case "network.show", "network.set", "network.confirm", "network.allowlist.reset", "keys.list",
			"admins.list", "recovery.add", "setup.recovery", "rootshell.begin", "rootshell.open", "product.value", "mcp.show", "mcp.set", "updates.show", "updates.set", "disk.cleanup":
			return Result{}, true, ErrUnavailable
		}
		return Result{}, false, nil
	}
	var (
		res Result
		err error
	)
	switch r.Action {
	case "status":
		res, err = s.status(ctx)
	case "network.show":
		res, err = s.networkShow(ctx)
	case "network.set":
		res, err = s.networkSet(ctx, r.Args)
	case "network.confirm":
		_, err = s.Network.ConfirmNetwork(ctx, connect.NewRequest(&accessv1.ConfirmNetworkRequest{Token: r.Args[0]}))
		res = Result{Text: "Kept."}
	case "network.allowlist.reset":
		var out *connect.Response[accessv1.ResetAllowListResponse]
		out, err = s.Network.ResetAllowList(ctx, connect.NewRequest(&accessv1.ResetAllowListRequest{}))
		if err == nil {
			t := out.Msg.GetToken()
			res = Result{Text: fmt.Sprintf("The allow-list is the management subnets now. It reverts in %d seconds unless kept: network confirm %s", out.Msg.GetRevertAfterSeconds(), t), Data: map[string]string{"token": t}}
		}
	case "keys.list":
		res, err = s.keysList(ctx, r.Flags["admin"])
	case "admins.list":
		res, err = s.adminsList(ctx)
	case "recovery.add":
		var out *connect.Response[accessv1.AddRecoveryKeyResponse]
		out, err = s.Access.AddRecoveryKey(ctx, connect.NewRequest(&accessv1.AddRecoveryKeyRequest{PublicKey: string(r.Stdin), Label: r.Flags["label"]}))
		if err == nil {
			res = Result{Text: "Recovery key " + out.Msg.GetRecoveryKey().GetFingerprint() + " added; a new escrow file was written."}
		}
	case "setup.recovery":
		var out *connect.Response[accessv1.SetRecoveryKeyResponse]
		out, err = s.Setup.SetRecoveryKey(ctx, connect.NewRequest(&accessv1.SetRecoveryKeyRequest{PublicKey: string(r.Stdin), Label: r.Flags["label"]}))
		if err == nil {
			res = Result{Text: "Recovery key " + out.Msg.GetRecoveryKey().GetFingerprint() + " set; a new escrow file was written."}
		}
	case "rootshell.begin", "rootshell.open":
		res, err = s.rootShell(ctx, r)
	case "product.value":
		res, err = s.productValue(ctx, r.Args[0])
	case "mcp.show":
		res, err = s.mcpShow(ctx)
	case "mcp.set":
		res, err = s.mcpSet(ctx, r.Args[0] == "on", r.Flags["machine-api"])
	case "updates.show":
		res, err = s.updatesShow(ctx)
	case "updates.set":
		res, err = s.updatesSet(ctx, r.Flags)
	case "disk.cleanup":
		res, err = s.diskCleanup(ctx)
	default:
		return Result{}, false, nil
	}
	if err != nil {
		if _, coded := codes.Of(err); r.Action == "status" && !coded && unavailable(err) {
			res, err = s.cachedStatus()
			return res, true, err
		}
		return Result{}, true, fromAccessd(err)
	}
	return res, true, nil
}

// productValue prints one value the product exposes, with the link that
// takes it; a one-time value that was used prints only that.
func (s *Services) productValue(ctx context.Context, name string) (Result, error) {
	out, err := s.Access.GetExposedValue(ctx, connect.NewRequest(&accessv1.GetExposedValueRequest{Name: name}))
	if err != nil {
		return Result{}, err
	}
	m := out.Msg.GetValue()
	e := m.GetEntry()
	label := Printable(e.GetLabel())
	if label == "" {
		label = Printable(m.GetProductTitle()) + "'s " + Printable(e.GetName())
	}
	if e.GetConsumed() {
		return Result{Text: label + " was already used and removed; there's nothing to show.", Data: map[string]any{"name": e.GetName(), "consumed": true}}, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n\n    %s\n", label, Printable(m.GetValue()))
	if link := Printable(e.GetLink()); link != "" {
		fmt.Fprintf(&b, "\nUse it at %s\n", link)
	}
	if e.GetOneTime() {
		b.WriteString("It works once; after that it's removed.\n")
	}
	return Result{Text: b.String(), Data: map[string]any{"name": e.GetName(), "consumed": false, "value": m.GetValue(), "link": e.GetLink()}}, nil
}

func (s *Services) mcpShow(ctx context.Context) (Result, error) {
	out, err := s.Access.GetMcp(ctx, connect.NewRequest(&accessv1.GetMcpRequest{}))
	if err != nil {
		return Result{}, err
	}
	m := out.Msg.GetMcp()
	word := map[bool]string{true: "on", false: "off"}
	text := fmt.Sprintf("%-12s %s\n%-12s %s\n", "MCP", Printable(m.GetState()), "machine API", word[m.GetMachineApiEnabled()])
	return Result{Text: text, Data: map[string]any{"state": m.GetState(), "mcp": m.GetMcpEnabled(), "machineApi": m.GetMachineApiEnabled()}}, nil
}

// mcpSet sets the switch; an empty api keeps the machine API as it is.
func (s *Services) mcpSet(ctx context.Context, on bool, api string) (Result, error) {
	cur, err := s.Access.GetMcp(ctx, connect.NewRequest(&accessv1.GetMcpRequest{}))
	if err != nil {
		return Result{}, err
	}
	machine := cur.Msg.GetMcp().GetMachineApiEnabled()
	if api != "" {
		machine = api == "on"
	}
	if _, err := s.Access.SetMcp(ctx, connect.NewRequest(&accessv1.SetMcpRequest{McpEnabled: on, MachineApiEnabled: machine})); err != nil {
		return Result{}, err
	}
	word := map[bool]string{true: "on", false: "off"}
	return Result{Text: fmt.Sprintf("MCP is %s; the machine API is %s.", word[on], word[machine]), Data: map[string]any{"mcp": on, "machineApi": machine}}, nil
}

// updatesShow prints the GitHub update source's channel, repository and
// the release last picked.
func (s *Services) updatesShow(ctx context.Context) (Result, error) {
	out, err := s.Access.GetUpdateChannel(ctx, connect.NewRequest(&accessv1.GetUpdateChannelRequest{}))
	if err != nil {
		return Result{}, err
	}
	m := out.Msg.GetMirrorStatus()
	channel := Printable(m.GetReleaseChannel())
	if m.GetReleaseChannelDefault() {
		channel += " (the default for this build)"
	}
	repo, tag := Printable(m.GetReleaseRepo()), Printable(m.GetReleaseTag())
	if repo == "" {
		repo = "none (this build has no GitHub source)"
	}
	if tag == "" {
		tag = "none picked yet"
	}
	text := fmt.Sprintf("%-12s %s\n%-12s %s\n%-12s %s\n%-12s %s\n", "source", Printable(out.Msg.GetPolicy().GetSource()), "channel", channel, "repository", repo, "release", tag)
	if t := m.GetRateLimitedUntil(); t != nil {
		text += fmt.Sprintf("%-12s used up until %s UTC\n", "rate limit", t.AsTime().UTC().Format("15:04:05"))
	}
	return Result{Text: text, Data: map[string]any{"source": out.Msg.GetPolicy().GetSource(), "channel": m.GetReleaseChannel(), "channelDefault": m.GetReleaseChannelDefault(),
		"repo": m.GetReleaseRepo(), "release": m.GetReleaseTag()}}, nil
}

// updatesSet sets the channel or the repository override, whichever the
// flags carry; the rest of the policy is kept.
func (s *Services) updatesSet(ctx context.Context, flags map[string]string) (Result, error) {
	req := &accessv1.SetUpdateChannelRequest{}
	text := ""
	if v, ok := flags["channel"]; ok {
		req.ReleaseChannel = &v
		text = "The update channel is " + map[bool]string{true: "the default", false: v}[v == ""] + "."
	}
	if v, ok := flags["repo"]; ok {
		req.ReleaseRepo = &v
		text = "The GitHub repository is " + map[bool]string{true: "the build's own", false: v}[v == ""] + "."
	}
	if _, err := s.Access.SetUpdateChannel(ctx, connect.NewRequest(req)); err != nil {
		return Result{}, err
	}
	return Result{Text: text, Data: flags}, nil
}

// diskCleanup runs the disk cleanup and prints what each step freed.
func (s *Services) diskCleanup(ctx context.Context) (Result, error) {
	out, err := s.Access.CleanUpDisk(ctx, connect.NewRequest(&accessv1.CleanUpDiskRequest{}))
	if err != nil {
		return Result{}, err
	}
	c := out.Msg.GetCleanup()
	var b strings.Builder
	fmt.Fprintf(&b, "Freed %s.\n", diskBytes(c.GetFreedBytes()))
	cats := []map[string]any{}
	for _, cat := range c.GetCategories() {
		line := fmt.Sprintf("  %-10s %s", Printable(cat.GetName()), diskBytes(cat.GetFreedBytes()))
		switch {
		case cat.GetError() != "":
			line += "  failed: " + Printable(cat.GetError())
		case cat.GetNote() != "":
			line += "  " + Printable(cat.GetNote())
		}
		b.WriteString(line + "\n")
		cats = append(cats, map[string]any{"name": cat.GetName(), "freedBytes": cat.GetFreedBytes(), "note": cat.GetNote(), "error": cat.GetError()})
	}
	return Result{Text: b.String(), Data: map[string]any{"freedBytes": c.GetFreedBytes(), "categories": cats}}, nil
}

// diskBytes is n in binary units, one decimal.
func diskBytes(n uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, u := float64(n), 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	if u == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[u])
}

func (s *Services) rootShell(ctx context.Context, r Request) (Result, error) {
	if r.Action == "rootshell.begin" {
		out, err := s.Elevation.BeginRootShell(ctx, connect.NewRequest(&accessv1.BeginRootShellRequest{Reason: r.Flags["reason"]}))
		if err != nil {
			return Result{}, err
		}
		m := out.Msg
		where := m.GetUrl()
		if where == "" {
			where = "the Root shell page on :8443"
		}
		text := fmt.Sprintf("Root shell %s. Open %s, paste this challenge and give a new authenticator code there:\n\n    %s\n\nIt works until %s UTC. Then type the code it gives you here.",
			m.GetId(), where, m.GetChallenge(), m.GetExpires().AsTime().UTC().Format("15:04:05"))
		return Result{Text: text, Data: map[string]string{"id": m.GetId(), "challenge": m.GetChallenge(), "url": m.GetUrl()}}, nil
	}
	out, err := s.Elevation.OpenRootShell(ctx, connect.NewRequest(&accessv1.OpenRootShellRequest{Challenge: r.Args[0], Code: r.Args[1]}))
	if err != nil {
		return Result{}, err
	}
	return Result{Text: "Opening the root shell.", Data: map[string]string{"ticket": out.Msg.GetTicket(), "socket": out.Msg.GetSocket(), "id": out.Msg.GetId()}}, nil
}

func unavailable(err error) bool {
	ce := new(connect.Error)
	if !errors.As(err, &ce) {
		return true
	}
	switch ce.Code() {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return true
	}
	return false
}

// fromAccessd turns accessd's error into the coded error it names; a
// silent accessd is ErrUnavailable.
func fromAccessd(err error) error {
	if _, ok := codes.Of(err); ok {
		return err
	}
	if unavailable(err) {
		return ErrUnavailable
	}
	return fromDaemon(err, "accessd")
}

func (s *Services) status(ctx context.Context) (Result, error) {
	out, err := s.Access.GetStatus(ctx, connect.NewRequest(&accessv1.GetStatusRequest{}))
	if err != nil {
		return Result{}, err
	}
	return statusResult(out.Msg.GetStatus(), ""), nil
}

// cachedStatus is status while accessd is down: the last one it kept.
func (s *Services) cachedStatus() (Result, error) {
	if s.StatusFile == "" {
		return Result{}, ErrUnavailable
	}
	c, err := accessapi.ReadStatusCache(s.StatusFile)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	note := fmt.Sprintf("The %s. This is the status from %s.", strings.TrimPrefix(accessapi.Unavailable, "the "), c.Saved.UTC().Format(time.RFC3339))
	return statusResult(c.Status, note), nil
}

func statusResult(st *osadminv1.GetStatusResponse, note string) Result {
	var b strings.Builder
	if note != "" {
		b.WriteString(note + "\n")
	}
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%-12s %s\n", k, Printable(v))
		}
	}
	row("Host", st.GetHostname())
	ver := st.GetVersion()
	if st.GetStagedVersion() != "" {
		ver += " (staged " + st.GetStagedVersion() + ")"
	}
	row("Version", ver)
	row("Phase", st.GetPhase())
	if p := st.GetProtection(); p != osadminv1.Protection_PROTECTION_UNSPECIFIED {
		row("Protection", strings.ToLower(strings.TrimPrefix(p.String(), "PROTECTION_"))+" "+st.GetCustodyMode())
	}
	row("Addresses", strings.Join(st.GetManagementAddresses(), ", "))
	if st.GetHostname() != "" {
		row("NTP", map[bool]string{true: "synchronised", false: "not synchronised"}[st.GetNtpSynced()])
	}
	for _, c := range st.GetHealth() {
		state := "ok"
		if !c.GetOk() {
			state = "down: " + c.GetDetail()
		}
		row("Health", c.GetName()+" "+state)
	}
	for _, w := range st.GetWarnings() {
		row("Warning", w.GetDetail())
	}
	data := map[string]any{}
	if raw, err := protojson.Marshal(st); err == nil {
		data["status"] = json.RawMessage(raw)
	}
	if note != "" {
		data["cached"] = true
	}
	return Result{Text: b.String(), Data: data}
}

func (s *Services) networkShow(ctx context.Context) (Result, error) {
	out, err := s.Network.GetNetwork(ctx, connect.NewRequest(&accessv1.GetNetworkRequest{}))
	if err != nil {
		return Result{}, err
	}
	st := out.Msg.GetSettings()
	var b strings.Builder
	row := func(k string, v ...string) {
		fmt.Fprintf(&b, "%-12s %s\n", k, Printable(strings.Join(v, ", ")))
	}
	row("hostname", st.GetHostname())
	row("addresses", out.Msg.GetManagementAddresses()...)
	row("dns", st.GetDns()...)
	row("search", st.GetSearch()...)
	row("ntp", st.GetNtp()...)
	row("allow-list", st.GetAllowList()...)
	row("time-zone", st.GetTimeZone())
	row("https-proxy", st.GetHttpsProxy())
	data := map[string]any{}
	if raw, err := protojson.Marshal(out.Msg); err == nil {
		data["network"] = json.RawMessage(raw)
	}
	return Result{Text: b.String(), Data: data}, nil
}

// networkSet applies key=value pairs on top of the current settings. The
// interfaces' addressing is set on :8443 or the console's network screen.
func (s *Services) networkSet(ctx context.Context, args []string) (Result, error) {
	cur, err := s.Network.GetNetwork(ctx, connect.NewRequest(&accessv1.GetNetworkRequest{}))
	if err != nil {
		return Result{}, err
	}
	st := cur.Msg.GetSettings()
	if st == nil {
		st = &netdv1.Settings{}
	}
	kvs, err := parseKeys("network set", networkKeys, args)
	if err != nil {
		return Result{}, err
	}
	for _, kv := range kvs {
		kv.key.set(st, kv.value)
	}
	out, err := s.Network.SetNetwork(ctx, connect.NewRequest(&accessv1.SetNetworkRequest{Settings: st}))
	if err != nil {
		return Result{}, err
	}
	t := out.Msg.GetToken()
	if t == "" {
		// netd kept it at once (no revert window, such as the time zone).
		return Result{Text: "Applied and kept; there's nothing to confirm.", Data: map[string]string{"token": ""}}, nil
	}
	return Result{Text: fmt.Sprintf("Applied. It reverts in %d seconds unless kept.", out.Msg.GetRevertAfterSeconds()), Data: map[string]string{"token": t}}, nil
}

func (s *Services) keysList(ctx context.Context, admin string) (Result, error) {
	out, err := s.Access.ListKeys(ctx, connect.NewRequest(&accessv1.ListKeysRequest{Admin: admin}))
	if err != nil {
		return Result{}, err
	}
	var b strings.Builder
	var data []map[string]string
	for _, k := range out.Msg.GetKeys() {
		fmt.Fprintf(&b, "%s  %s  %s\n", k.GetFingerprint(), k.GetType(), Printable(k.GetComment()))
		data = append(data, map[string]string{"fingerprint": k.GetFingerprint(), "type": k.GetType(), "comment": k.GetComment(), "via": k.GetVia()})
	}
	if len(data) == 0 {
		b.WriteString(out.Msg.GetAdmin() + " has no login keys.\n")
	}
	return Result{Text: b.String(), Data: map[string]any{"admin": out.Msg.GetAdmin(), "keys": data}}, nil
}

func (s *Services) adminsList(ctx context.Context) (Result, error) {
	out, err := s.Access.ListAdmins(ctx, connect.NewRequest(&accessv1.ListAdminsRequest{}))
	if err != nil {
		return Result{}, err
	}
	var b strings.Builder
	var data []map[string]any
	for _, a := range out.Msg.GetAdmins() {
		role := roleWord(a.GetRole())
		fmt.Fprintf(&b, "%-20s %-6s %d key(s)\n", a.GetName(), role, len(a.GetKeys()))
		data = append(data, map[string]any{"name": a.GetName(), "role": role, "uid": a.GetUid(), "keys": len(a.GetKeys())})
	}
	return Result{Text: b.String(), Data: data}, nil
}

func roleWord(r osadminv1.Role) string {
	switch r {
	case osadminv1.Role_ROLE_OWNER:
		return "owner"
	case osadminv1.Role_ROLE_ADMIN:
		return "admin"
	}
	return "?"
}
