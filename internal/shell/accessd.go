// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
		case "network.show", "network.set", "network.confirm", "network.allowlist.reset", "keys.list", "keys.add", "keys.remove",
			"admins.list", "admins.add", "admins.remove", "recovery.add", "setup.recovery", "elevation.request", "elevation.status", "elevation.cert":
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
	case "keys.add":
		var out *connect.Response[accessv1.AddKeyResponse]
		out, err = s.Access.AddKey(ctx, connect.NewRequest(&accessv1.AddKeyRequest{Admin: r.Flags["admin"], PublicKey: string(r.Stdin)}))
		if err == nil {
			res = Result{Text: "Added " + out.Msg.GetKey().GetFingerprint() + ".", Data: map[string]string{"fingerprint": out.Msg.GetKey().GetFingerprint()}}
		}
	case "keys.remove":
		_, err = s.Access.RemoveKey(ctx, connect.NewRequest(&accessv1.RemoveKeyRequest{Admin: r.Flags["admin"], Fingerprint: r.Args[0]}))
		res = Result{Text: "Removed."}
	case "admins.list":
		res, err = s.adminsList(ctx)
	case "admins.add":
		res, err = s.adminsAdd(ctx, r.Args[0], r.Flags["role"])
	case "admins.remove":
		_, err = s.Access.RemoveAdmin(ctx, connect.NewRequest(&accessv1.RemoveAdminRequest{Name: r.Args[0]}))
		res = Result{Text: "Removed " + r.Args[0] + "."}
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
	case "elevation.request", "elevation.status", "elevation.cert":
		res, err = s.elevation(ctx, r)
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

func (s *Services) elevation(ctx context.Context, r Request) (Result, error) {
	switch r.Action {
	case "elevation.request":
		m, _ := strconv.Atoi(r.Flags["minutes"])
		out, err := s.Elevation.RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: int32(min(max(m, 0), 240)), Reason: r.Flags["reason"]})) // #nosec G115 -- clamped
		if err != nil {
			return Result{}, err
		}
		e := out.Msg.GetElevation()
		return Result{Text: fmt.Sprintf("Requested %s (%d minutes). An owner approves it; then run: elevation cert %s", e.GetId(), e.GetMinutes(), e.GetId()), Data: map[string]string{"id": e.GetId(), "state": e.GetState()}}, nil
	case "elevation.status":
		out, err := s.Elevation.ListElevations(ctx, connect.NewRequest(&accessv1.ListElevationsRequest{}))
		if err != nil {
			return Result{}, err
		}
		var b strings.Builder
		var data []map[string]string
		for _, e := range out.Msg.GetElevations() {
			if len(r.Args) == 1 && e.GetId() != r.Args[0] {
				continue
			}
			fmt.Fprintf(&b, "%s  %s  %s  %d min  %s\n", e.GetId(), e.GetState(), e.GetAdmin(), e.GetMinutes(), Printable(e.GetReason()))
			data = append(data, map[string]string{"id": e.GetId(), "state": e.GetState(), "admin": e.GetAdmin()})
		}
		return Result{Text: b.String(), Data: data}, nil
	}
	out, err := s.Elevation.GetElevationCertificate(ctx, connect.NewRequest(&accessv1.GetElevationCertificateRequest{Id: r.Args[0]}))
	if err != nil {
		return Result{}, err
	}
	return Result{Text: out.Msg.GetCertificate() + "\n" + out.Msg.GetLogin(), Data: map[string]string{"certificate": out.Msg.GetCertificate(), "login": out.Msg.GetLogin()}}, nil
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
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return Result{}, codes.New(codes.ShellParse, "%q isn't key=value", a)
		}
		list := func() []string {
			if v == "" {
				return nil
			}
			return strings.Split(v, ",")
		}
		switch k {
		case "hostname":
			st.Hostname = v
		case "dns":
			st.Dns = list()
		case "search":
			st.Search = list()
		case "ntp":
			st.Ntp = list()
		case "allow-list":
			st.AllowList = list()
		case "time-zone":
			st.TimeZone = v
		case "https-proxy":
			st.HttpsProxy = v
		default:
			return Result{}, codes.New(codes.ShellParse, "%q isn't a setting the shell changes (hostname, dns, search, ntp, allow-list, time-zone, https-proxy); set the interfaces on :8443", k)
		}
	}
	out, err := s.Network.SetNetwork(ctx, connect.NewRequest(&accessv1.SetNetworkRequest{Settings: st}))
	if err != nil {
		return Result{}, err
	}
	t := out.Msg.GetToken()
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

func (s *Services) adminsAdd(ctx context.Context, name, role string) (Result, error) {
	var r osadminv1.Role
	switch role {
	case "owner":
		r = osadminv1.Role_ROLE_OWNER
	case "admin", "":
		r = osadminv1.Role_ROLE_ADMIN
	default:
		return Result{}, codes.New(codes.ShellParse, "--role is owner or admin")
	}
	out, err := s.Access.AddAdmin(ctx, connect.NewRequest(&accessv1.AddAdminRequest{Name: name, Role: r}))
	if err != nil {
		return Result{}, err
	}
	a := out.Msg.GetAdmin()
	return Result{Text: fmt.Sprintf("Added %s (%s). Add a login key with: keys add --admin %s", a.GetName(), roleWord(a.GetRole()), a.GetName())}, nil
}
