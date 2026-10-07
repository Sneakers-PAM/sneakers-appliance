// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	netmodel "github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

type status struct {
	osadminv1connect.UnimplementedStatusServiceHandler
	s *Server
}

func (h *status) GetStatus(ctx context.Context, _ *connect.Request[osadminv1.GetStatusRequest]) (*connect.Response[osadminv1.GetStatusResponse], error) {
	s := h.s
	cert := s.cert()
	out := &osadminv1.GetStatusResponse{
		Version: release.Version, Channel: release.Channel, Phase: "firstboot",
		TlsFingerprint: cert.Fingerprint, TlsSelfSigned: cert.SelfSigned,
	}
	if !cert.Expires.IsZero() {
		out.TlsExpires = timestamppb.New(cert.Expires)
	}
	if s.SetupDone() {
		out.Phase = "normal"
	}
	add := func(kind osadminv1.WarningKind, detail string) {
		out.Warnings = append(out.Warnings, &osadminv1.Warning{Kind: kind, Detail: detail})
	}
	health := func(name string, err error) {
		c := &osadminv1.Component{Name: name, Ok: err == nil}
		if err != nil {
			c.Detail = err.Error()
			s.o.Logger.Warn("osadmin: status: a component didn't answer", log.F("component", name), log.F("error", err.Error()))
		}
		out.Health = append(out.Health, c)
	}

	ns, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	health("netd", err)
	if err == nil {
		out.Hostname, out.ManagementAddresses, out.NtpSynced = ns.Msg.GetHostname(), ns.Msg.GetManagementAddresses(), ns.Msg.GetNtpSynced()
		if !out.NtpSynced {
			add(osadminv1.WarningKind_WARNING_KIND_NTP_UNSYNCED, "The clock isn't synchronised with an NTP server.")
		}
		if ng, gerr := s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{})); gerr == nil && exposed(out.ManagementAddresses, ng.Msg.GetSettings().GetAllowList()) {
			add(osadminv1.WarningKind_WARNING_KIND_EXPOSURE, "The management interface has a public address and the allow-list lets any source reach ports 22 and 8443.")
		}
	}

	prot, err := s.o.KeyCustody.Protection(ctx, connect.NewRequest(&initv1.ProtectionRequest{}))
	health("init", err)
	if err == nil {
		switch prot.Msg.GetLevel() {
		case initv1.ProtectionLevel_PROTECTION_LEVEL_FULL:
			out.Protection = osadminv1.Protection_PROTECTION_FULL
		case initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED:
			out.Protection = osadminv1.Protection_PROTECTION_REDUCED
			add(osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION, "Reduced protection: "+prot.Msg.GetReason()+".")
		}
		out.ProtectionReason = prot.Msg.GetReason()
		if m, merr := s.o.KeyCustody.Mode(ctx, connect.NewRequest(&initv1.ModeRequest{})); merr == nil {
			switch m.Msg.GetMode() {
			case initv1.CustodyMode_CUSTODY_MODE_TPM:
				out.CustodyMode = "tpm"
			case initv1.CustodyMode_CUSTODY_MODE_KEYFILE:
				out.CustodyMode = "keyfile"
			}
		}
	}
	if img, ierr := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{})); ierr == nil {
		out.RunningVersion, out.StagedVersion, out.FailedVersion = img.Msg.GetRunningVersion(), img.Msg.GetStagedVersion(), img.Msg.GetFailedVersion()
	}
	if cert.SelfSigned {
		add(osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS, "This page uses the box's own self-signed certificate; check its fingerprint.")
	}
	now := s.o.Clock.Now()
	for _, a := range s.o.Access.Read().Admins {
		if a.ApprovalHoldUntil != nil && now.Before(*a.ApprovalHoldUntil) {
			add(osadminv1.WarningKind_WARNING_KIND_CONSOLE_RECOVERY, "A key for "+a.Name+" was added on the console with Recover access.")
		}
	}
	if fr := s.FactoryReset(); fr != nil {
		out.FactoryReset = fr
		detail := "A factory reset requested by " + fr.GetStartedBy() + " is waiting for its quorum."
		if fr.GetState() == osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN {
			detail = "A factory reset requested by " + fr.GetStartedBy() + " runs at " + fr.GetRunsAt().AsTime().UTC().Format(time.RFC3339) + " unless an admin cancels it."
		}
		add(osadminv1.WarningKind_WARNING_KIND_FACTORY_RESET, detail)
	}
	out.Disk = s.disk()
	return connect.NewResponse(out), nil
}

func exposed(mgmt, allow []string) bool {
	var as []netip.Addr
	for _, m := range mgmt {
		if a, err := netip.ParseAddr(m); err == nil {
			as = append(as, a)
		} else if p, err := netip.ParsePrefix(m); err == nil {
			as = append(as, p.Addr())
		}
	}
	var ps []netip.Prefix
	for _, a := range allow {
		if p, err := netip.ParsePrefix(a); err == nil {
			ps = append(ps, p)
		}
	}
	return netmodel.Exposed(as, ps)
}

// diskSamples is one used-bytes sample per UTC day, oldest first.
type diskSample struct {
	Day  string `json:"day"`
	Used uint64 `json:"used"`
}

const diskSamplesFile = "disk-samples.json"

// disk reads the state volume's use and records today's sample, keeping a
// week, so Status can show the daily growth.
func (s *Server) disk() *osadminv1.Disk {
	var fs unix.Statfs_t
	if err := unix.Statfs(s.o.Paths.State, &fs); err != nil {
		s.o.Logger.Warn("osadmin: statfs failed", log.F("path", s.o.Paths.State), log.F("error", err.Error()))
		return nil
	}
	bs := uint64(fs.Bsize) // #nosec G115 -- a block size is positive
	total, used := fs.Blocks*bs, (fs.Blocks-fs.Bfree)*bs
	d := &osadminv1.Disk{Path: s.o.Paths.State, UsedBytes: used, TotalBytes: total}
	p := filepath.Join(s.o.Paths.APIDir(), diskSamplesFile)
	var samples []diskSample
	if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- osadmin's own file
		_ = json.Unmarshal(b, &samples)
	}
	today := s.o.Clock.Now().UTC().Format(time.DateOnly)
	if i := slices.IndexFunc(samples, func(x diskSample) bool { return x.Day == today }); i < 0 {
		samples = append(samples, diskSample{Day: today, Used: used})
		if len(samples) > 8 {
			samples = samples[len(samples)-8:]
		}
		if b, err := json.Marshal(samples); err == nil {
			if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err == nil {
				if err := writeAtomic(p, b); err != nil {
					s.o.Logger.Warn("osadmin: disk sample not saved", log.F("error", err.Error()))
				}
			}
		}
	}
	if len(samples) >= 2 {
		first, last := samples[0], samples[len(samples)-1]
		t0, e0 := time.Parse(time.DateOnly, first.Day)
		t1, e1 := time.Parse(time.DateOnly, last.Day)
		if days := int64(t1.Sub(t0).Hours() / 24); e0 == nil && e1 == nil && days > 0 {
			d.GrowthBytesPerDay = (int64(last.Used) - int64(first.Used)) / days // #nosec G115 -- disk sizes fit an int64
		}
	}
	return d
}

func (h *status) SetSecureBoot(ctx context.Context, r *connect.Request[osadminv1.SetSecureBootRequest]) (*connect.Response[osadminv1.SetSecureBootResponse], error) {
	c := callFrom(ctx)
	on := "off"
	if r.Msg.GetOn() {
		on = "on"
	}
	c.note("secure-boot", "on", on)
	if err := h.s.confirmHostname(ctx, r.Msg.GetConfirmHostname()); err != nil {
		return nil, err
	}
	if _, err := h.s.o.KeyCustody.SetSecureBoot(ctx, connect.NewRequest(&initv1.SetSecureBootRequest{On: r.Msg.GetOn()})); err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: Secure Boot setting changed", log.F("on", on), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.SetSecureBootResponse{}), nil
}

// confirmHostname checks a typed confirmation against the box's host name.
func (s *Server) confirmHostname(ctx context.Context, typed string) error {
	st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return err
	}
	if st.Msg.GetHostname() == "" || typed != st.Msg.GetHostname() {
		return codes.New(codes.AccessConfirm, "type the box's host name to confirm")
	}
	return nil
}
