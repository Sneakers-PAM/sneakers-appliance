// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"filippo.io/age"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/basepatch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// MaxUpload caps an uploaded or fetched .bin.
const MaxUpload = 8 << 30

// The upgrade files in Paths.APIDir.
const (
	policyFile  = "upgrade-policy.json"
	historyFile = "upgrade-history.jsonl"
	uploadsDir  = "uploads"
)

var (
	uploadIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	windowRE   = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// UpgradeOptions are what the update flows need beyond the daemons.
type UpgradeOptions struct {
	// Channel and ReleaseKeyPEM are the running build's pins: a .bin must be
	// signed by this key for this channel.
	Channel       string
	ReleaseKeyPEM []byte
	// UpdateKey reads the .bin decryption key from the booted UKI. It is
	// called only after a package verifies.
	UpdateKey func() (age.Identity, error)
	// HTTPClient fetches from every source; nil builds a client per
	// fetch with the environment's proxy, the system roots and, for the
	// mirror, the update trust.
	HTTPClient *http.Client
	// SystemRoots stands in for the system's roots; nil reads them.
	SystemRoots *x509.CertPool
	// ElevationEndWait bounds how long an owner's override waits for the
	// elevated session it terminated to end; 0 is DefaultElevationEndWait.
	ElevationEndWait time.Duration
	// DirectURL is the release source (a production build's GitHub
	// Releases URL); empty when the build has none, as a lab build.
	DirectURL string
	// ProductDir holds the product slots; empty is product.Dir.
	ProductDir string
	// Arch is the box's architecture; empty is amd64.
	Arch string
	// ProductUpEvery is how often Options.ProductUp is asked while a
	// product comes up; 0 is DefaultProductUpEvery.
	ProductUpEvery time.Duration
}

// DefaultElevationEndWait is how long an override waits for a terminated
// elevated session's recording to close and its end to be reported.
const DefaultElevationEndWait = 30 * time.Second

// Policy is the update policy as stored.
type Policy struct {
	Mode          string `json:"mode"`
	WindowStart   string `json:"windowStart"`
	WindowMinutes int    `json:"windowMinutes"`
	MirrorURL     string `json:"mirrorUrl,omitempty"`
	Direct        bool   `json:"direct,omitempty"`
}

// DefaultPolicy is a new box's: automatic in a daily 02:00 window of two
// hours, no mirror (upload only).
func DefaultPolicy() Policy {
	return Policy{Mode: "automatic", WindowStart: "02:00", WindowMinutes: 120}
}

type historyEntry struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Version string    `json:"version,omitempty"`
	Actor   string    `json:"actor"`
	Outcome string    `json:"outcome"`
	Code    string    `json:"code,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Target  string    `json:"target,omitempty"`
}

// MaintenanceBound is how long an apply or revert that went through holds
// maintenance: the box is rebooting, and a reboot that never comes mustn't
// block elevation for ever.
const MaintenanceBound = 15 * time.Minute

type upgrades struct {
	mu sync.Mutex
	// lastWindow is the day (local) the window last applied a release, and
	// lastProductWindow a product bundle.
	lastWindow, lastProductWindow string
	// maintUntil is when the maintenance an apply or revert set ends.
	maintUntil time.Time
	// receiving counts the uploads and fetches coming in; staging is set
	// while a stage runs. Either, or a held upload, refuses a new upload
	// or fetch (UPGRADE_BUSY).
	receiving int
	staging   bool
}

// Maintenance reports an update being applied or reverted: the elevation
// service refuses new elevated shells meanwhile (ELEV_MAINTENANCE).
func (s *Server) Maintenance() bool {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	return s.o.Clock.Now().Before(s.upgrades.maintUntil)
}

// beginMaintenance sets maintenance, then refuses when an elevated shell
// is already active, naming it: the owner ends it, waits for it, or
// overrides. An override o names one active session, confirmed by typing
// its admin and id; that session is terminated, audited with the reason,
// and waited for before maintenance goes ahead. Any other active session
// still refuses. Setting maintenance before the check means none can start
// in between. It returns the id of the session the override ended.
func (s *Server) beginMaintenance(ctx context.Context, what string, by osaudit.Entry, o *osadminv1.ElevationOverride) (string, error) {
	s.upgrades.mu.Lock()
	s.upgrades.maintUntil = s.o.Clock.Now().Add(MaintenanceBound)
	s.upgrades.mu.Unlock()
	if s.o.Elevation == nil {
		return "", nil
	}
	var held *elevation.Request
	for _, r := range s.o.Elevation.List() {
		if r.State != elevation.Active {
			continue
		}
		if o != nil && r.ID == o.GetElevationId() {
			held = &r
			continue
		}
		s.endMaintenance()
		s.o.Logger.Warn("osadmin: an update waits for an elevated shell", log.F("what", what), log.F("elevation", r.ID), log.F("admin", r.Admin))
		return "", codes.New(codes.UpgradeElevated, "%s has an elevated shell open (%s); it must end, or an owner ends it with an override, before the %s", r.Admin, r.ID, what)
	}
	if held != nil {
		if err := s.overrideElevation(ctx, *held, by, o); err != nil {
			s.endMaintenance()
			return "", err
		}
	}
	s.o.Logger.Info("osadmin: maintenance on", log.F("what", what))
	if held == nil {
		return "", nil
	}
	return held.ID, nil
}

// overrideElevation checks the owner's typed confirmation and reason, ends
// r and waits until its end is reported, so nothing is applied under it.
func (s *Server) overrideElevation(ctx context.Context, r elevation.Request, by osaudit.Entry, o *osadminv1.ElevationOverride) error {
	want := r.Admin + " " + r.ID
	if strings.TrimSpace(o.GetConfirm()) != want {
		s.o.Logger.Warn("osadmin: an elevation override's confirmation doesn't match", log.F("elevation", r.ID), log.F("by", by.Actor))
		return codes.New(codes.AccessConfirm, "type %q to confirm ending %s's elevated shell", want, r.Admin)
	}
	reason := strings.TrimSpace(o.GetReason())
	if reason == "" || len(reason) > 500 {
		return codes.New(codes.AccessConfirm, "say why %s's elevated shell is ended, in at most 500 characters", r.Admin)
	}
	_, err := s.o.Elevation.Terminate(r.ID, by.Actor)
	e := by
	e.Action, e.Target = "elevation.terminate", r.Name()
	e.Detail = map[string]string{"request": r.ID, "admin": r.Admin, "reason": reason, "for": by.Action}
	if surface := by.Detail["surface"]; surface != "" {
		e.Detail["surface"] = surface
	}
	s.write(e, err)
	if err != nil {
		return err
	}
	s.o.Logger.Info("osadmin: an owner override ends an elevated shell", log.F("elevation", r.ID), log.F("admin", r.Admin), log.F("by", by.Actor), log.F("for", by.Action))
	wait := s.o.Upgrade.ElevationEndWait
	if wait <= 0 {
		wait = DefaultElevationEndWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if got, ok := s.o.Elevation.Get(r.ID); !ok || got.State != elevation.Active {
			s.o.Logger.Info("osadmin: the overridden elevated shell ended", log.F("elevation", r.ID))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			s.o.Logger.Warn("osadmin: the overridden elevated shell hasn't ended", log.F("elevation", r.ID), log.F("waited", wait.String()))
			return codes.New(codes.UpgradeElevated, "%s's elevated shell (%s) was told to end but is still open after %s; try again once it has ended", r.Admin, r.ID, wait)
		case <-tick.C:
		}
	}
}

func (s *Server) endMaintenance() {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	if !s.upgrades.maintUntil.IsZero() {
		s.upgrades.maintUntil = time.Time{}
		s.o.Logger.Info("osadmin: maintenance off")
	}
}

func (s *Server) ownPath(name string) string { return filepath.Join(s.o.Paths.APIDir(), name) }

func (s *Server) policy() Policy {
	p := DefaultPolicy()
	if b, err := os.ReadFile(s.ownPath(policyFile)); err == nil { // #nosec G304 -- osadmin's own file
		if err := json.Unmarshal(b, &p); err != nil {
			s.o.Logger.Error(err, "osadmin: the update policy doesn't parse; using the default")
			return DefaultPolicy()
		}
	}
	return p
}

func (s *Server) history(action, version, actor string, err error, detail string) {
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_BASE, action, version, actor, err, detail)
}

func targetName(t osadminv1.UpdateTarget) string {
	if t == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT {
		return "product"
	}
	return "base"
}

func (s *Server) historyFor(target osadminv1.UpdateTarget, action, version, actor string, err error, detail string) {
	e := historyEntry{Time: s.o.Clock.Now().UTC(), Action: action, Version: version, Actor: actor, Outcome: "ok", Detail: detail, Target: targetName(target)}
	if err != nil {
		e.Outcome, e.Code = "failed", symbolOf(err)
	}
	b, merr := json.Marshal(e)
	if merr != nil {
		return
	}
	if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err != nil {
		s.o.Logger.Error(err, "osadmin: upgrade history not written")
		return
	}
	f, ferr := os.OpenFile(s.ownPath(historyFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- osadmin's own file
	if ferr != nil {
		s.o.Logger.Error(ferr, "osadmin: upgrade history not written")
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Sync()
	_ = f.Close()
}

func (s *Server) readHistory(limit int) []*osadminv1.UpgradeEvent {
	f, err := os.Open(s.ownPath(historyFile)) // #nosec G304 -- osadmin's own file
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var all []*osadminv1.UpgradeEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e historyEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		target := osadminv1.UpdateTarget_UPDATE_TARGET_BASE
		if e.Target == "product" {
			target = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
		}
		all = append(all, &osadminv1.UpgradeEvent{Time: timestamppb.New(e.Time), Action: e.Action, Version: e.Version, Actor: e.Actor, Outcome: e.Outcome, Code: e.Code, Detail: e.Detail, Target: target})
	}
	slices.Reverse(all)
	if len(all) > limit {
		all = all[:limit]
	}
	return all
}

func (s *Server) uploadPath(id string) (string, error) {
	if !uploadIDRE.MatchString(id) {
		return "", codes.New(codes.UpgradeUpload, "%q isn't an upload this box made", id)
	}
	p := filepath.Join(s.o.Paths.APIDir(), uploadsDir, id+".bin")
	if _, err := os.Stat(p); err != nil {
		return "", codes.New(codes.UpgradeUpload, "there is no upload %s; upload or fetch the .bin again", id)
	}
	return p, nil
}

// uploadMeta is what's known of a held upload, kept next to its .bin.
type uploadMeta struct {
	Name   string    `json:"name,omitempty"`
	Size   int64     `json:"size"`
	At     time.Time `json:"at"`
	Source string    `json:"source"`
}

// uploadSource is where an upload came from: upload, mirror or direct.
func (s *Server) uploadSource(id string) string {
	var m uploadMeta
	if raw, err := os.ReadFile(filepath.Join(s.uploadsDir(), id+".json")); err == nil { // #nosec G304 -- an upload this box made
		_ = json.Unmarshal(raw, &m)
	}
	return m.Source
}

func (s *Server) uploadsDir() string { return filepath.Join(s.o.Paths.APIDir(), uploadsDir) }

// heldUpload is the newest upload or fetched file not yet staged or
// discarded, or nil when there's none.
func (s *Server) heldUpload() *osadminv1.HeldUpload {
	bins, _ := filepath.Glob(filepath.Join(s.uploadsDir(), "*.bin"))
	var out *osadminv1.HeldUpload
	var newest time.Time
	for _, b := range bins {
		id := strings.TrimSuffix(filepath.Base(b), ".bin")
		if !uploadIDRE.MatchString(id) {
			continue
		}
		var m uploadMeta
		if raw, err := os.ReadFile(strings.TrimSuffix(b, ".bin") + ".json"); err == nil { // #nosec G304 -- an upload this box made
			_ = json.Unmarshal(raw, &m)
		}
		if m.At.IsZero() {
			if fi, err := os.Stat(b); err == nil {
				m.At, m.Size = fi.ModTime(), fi.Size()
			}
		}
		if out == nil || m.At.After(newest) {
			newest = m.At
			out = &osadminv1.HeldUpload{UploadId: id, FileName: m.Name, Size: m.Size, ReceivedAt: timestamppb.New(m.At), Source: m.Source}
		}
	}
	return out
}

// reserveReceive takes the one place for a file coming in, or refuses
// with UPGRADE_BUSY while another is coming in or held or a stage runs.
// A partial file left by a crash is removed here, since nothing is coming
// in. The caller calls releaseReceive when the file is in.
func (s *Server) reserveReceive() error {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	switch {
	case s.upgrades.receiving > 0:
		return codes.New(codes.UpgradeBusy, "a file is already coming in; wait for it, or cancel it, first")
	case s.upgrades.staging:
		return codes.New(codes.UpgradeBusy, "a stage is under way; wait for it to finish first")
	}
	if h := s.heldUpload(); h != nil {
		name := h.GetFileName()
		if name == "" {
			name = "upload " + h.GetUploadId()
		}
		return codes.New(codes.UpgradeBusy, "a file is already waiting (%s); verify it or cancel it first", name)
	}
	tmps, _ := filepath.Glob(filepath.Join(s.uploadsDir(), "*.tmp"))
	for _, t := range tmps {
		s.o.Logger.Warn("osadmin: removing a partial upload left behind", log.F("file", filepath.Base(t)))
		_ = os.Remove(t)
	}
	s.upgrades.receiving++
	return nil
}

func (s *Server) releaseReceive() {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	s.upgrades.receiving--
}

// beginStaging marks a stage under way, or refuses with UPGRADE_BUSY when
// one already is or a file is still coming in.
func (s *Server) beginStaging() error {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	if s.upgrades.staging {
		return codes.New(codes.UpgradeBusy, "a stage is already under way")
	}
	if s.upgrades.receiving > 0 {
		return codes.New(codes.UpgradeBusy, "a file is still coming in; wait for it first")
	}
	s.upgrades.staging = true
	return nil
}

func (s *Server) endStaging() {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	s.upgrades.staging = false
}

func (s *Server) isStaging() bool {
	s.upgrades.mu.Lock()
	defer s.upgrades.mu.Unlock()
	return s.upgrades.staging
}

// saveUpload copies r (at most MaxUpload bytes) into a new upload, with
// what's known of it beside, and returns its id. A copy cut off (the
// browser aborted, the mirror stopped) removes its partial file.
func (s *Server) saveUpload(r io.Reader, meta uploadMeta) (string, int64, error) {
	dir := s.uploadsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, fmt.Errorf("upload: %w", err)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	final := filepath.Join(dir, id+".bin")
	f, err := os.OpenFile(final+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a new file in the uploads directory
	if err != nil {
		return "", 0, fmt.Errorf("upload: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxUpload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > MaxUpload {
		err = codes.New(codes.UpgradeUpload, "the file is over %d bytes", int64(MaxUpload))
	}
	if err != nil {
		_ = os.Remove(final + ".tmp")
		s.o.Logger.Info("osadmin: a partial upload was removed", log.F("upload", id), log.F("bytes", n))
		if _, coded := codes.Of(err); coded {
			return "", 0, err
		}
		return "", 0, codes.Wrap(codes.UpgradeUpload, err)
	}
	meta.Size, meta.At = n, s.o.Clock.Now().UTC()
	if mb, merr := json.Marshal(meta); merr == nil {
		if werr := os.WriteFile(filepath.Join(dir, id+".json"), mb, 0o600); werr != nil {
			s.o.Logger.Warn("osadmin: an upload's details weren't written", log.F("upload", id), log.F("error", werr.Error()))
		}
	}
	if err := os.Rename(final+".tmp", final); err != nil {
		return "", 0, fmt.Errorf("upload: %w", err)
	}
	return id, n, nil
}

// dropUpload removes everything an upload left: its .bin, a partial
// .tmp, an unpacked layout and its details. It reports whether there was
// anything.
func (s *Server) dropUpload(id string) bool {
	base := filepath.Join(s.uploadsDir(), id)
	found := false
	for _, p := range []string{base + ".bin", base + ".bin.tmp", base + ".d", base + ".json"} {
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		found = true
		s.removeUpload(p)
	}
	return found
}

// uploadName is the file name the page sends with an upload, for the
// held upload's card only: its last path element, printable, at most 200
// bytes.
func uploadName(h string) string {
	if v, err := url.PathUnescape(h); err == nil {
		h = v
	}
	h = filepath.Base(strings.ReplaceAll(h, "\\", "/"))
	h = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, h)
	if h == "." || h == "/" {
		return ""
	}
	if len(h) > 200 {
		h = h[:200]
	}
	return h
}

// handleUpload is POST /upload: the .bin as the body, the session cookie
// and the CSRF header, and the file's name in X-File-Name. While another
// file is coming in or held, or a stage runs, it answers 409 with
// UPGRADE_BUSY.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	entry := osaudit.Entry{Source: hostOf(r.RemoteAddr), Action: "upgrade.upload"}
	sess, err := s.session(r.Header)
	if err == nil {
		entry.Actor = sess.Admin
		_, err = s.liveRole(sess)
	}
	if err == nil && subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(sess.CSRF)) != 1 {
		err = codes.New(codes.AccessForbidden, "the request's CSRF token is missing or wrong; reload the page")
	}
	if err != nil {
		s.write(entry, err)
		http.Error(w, codes.Describe(err), http.StatusForbidden)
		return
	}
	if err := s.reserveReceive(); err != nil {
		entry.Target = "uploaded file"
		s.write(entry, err)
		s.o.Logger.Info("osadmin: upload refused while another is in hand", log.F("by", sess.Admin), log.F("error", describe(err)))
		http.Error(w, describe(err), http.StatusConflict)
		return
	}
	defer s.releaseReceive()
	name := uploadName(r.Header.Get("X-File-Name"))
	id, n, err := s.saveUpload(http.MaxBytesReader(w, r.Body, MaxUpload+1), uploadMeta{Name: name, Source: "upload"})
	entry.Target = "uploaded file"
	entry.Detail = map[string]string{"upload": id, "bytes": strconv.FormatInt(n, 10)}
	if name != "" {
		entry.Detail["name"] = name
	}
	s.write(entry, err)
	if err != nil {
		s.o.Logger.Warn("osadmin: upload failed", log.F("error", describe(err)))
		http.Error(w, describe(err), http.StatusBadRequest)
		return
	}
	s.o.Logger.Info("osadmin: update uploaded", log.F("upload", id), log.F("bytes", n), log.F("by", sess.Admin))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"uploadId": id})
}

type upgradeSvc struct {
	osadminv1connect.UnimplementedUpgradeServiceHandler
	s *Server
}

func policyToWire(p Policy) *osadminv1.UpgradePolicy {
	return &osadminv1.UpgradePolicy{Mode: p.Mode, WindowStart: p.WindowStart, WindowMinutes: int32(min(p.WindowMinutes, 1<<30)), MirrorUrl: p.MirrorURL, Direct: p.Direct} // #nosec G115 -- clamped
}

func (h *upgradeSvc) GetUpgrades(ctx context.Context, _ *connect.Request[osadminv1.GetUpgradesRequest]) (*connect.Response[osadminv1.GetUpgradesResponse], error) {
	p := h.s.policy()
	direct := h.s.o.Upgrade.DirectURL != ""
	out := &osadminv1.GetUpgradesResponse{Policy: policyToWire(p), AirGapped: p.MirrorURL == "" && (!p.Direct || !direct), History: h.s.readHistory(100),
		Product: h.s.productSlots(ctx), DirectAvailable: direct, MirrorStatus: h.s.mirrorStatus(p), HeldUpload: h.s.heldUpload()}
	h.s.upgrades.mu.Lock()
	out.Receiving = h.s.upgrades.receiving > 0
	h.s.upgrades.mu.Unlock()
	if st, err := h.s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{})); err == nil {
		out.RunningVersion, out.StagedVersion, out.FailedVersion = st.Msg.GetRunningVersion(), st.Msg.GetStagedVersion(), st.Msg.GetFailedVersion()
		out.RevertedVersion, out.RevertedBy, out.RevertedAt = st.Msg.GetRevertedVersion(), st.Msg.GetRevertedBy(), st.Msg.GetRevertedAt()
		out.PreviousVersion, out.PreviousSlot = h.s.previous(st.Msg)
		out.NextStageRemoves = st.Msg.GetNextStageRemoves()
		out.UpgradeProgress = h.s.progressToWire(st.Msg)
	} else {
		out.UpgradeProgress = h.s.progressToWire(nil)
	}
	if h.s.o.Elevation != nil {
		auditDir := ""
		if h.s.o.Audit != nil {
			auditDir = h.s.o.Audit.Dir()
		}
		for _, r := range h.s.o.Elevation.List() {
			if r.State == elevation.Active {
				out.ActiveElevations = append(out.ActiveElevations, ElevationToWire(r, auditDir))
			}
		}
	}
	return connect.NewResponse(out), nil
}

func (h *upgradeSvc) SetUpgradePolicy(ctx context.Context, r *connect.Request[osadminv1.SetUpgradePolicyRequest]) (*connect.Response[osadminv1.SetUpgradePolicyResponse], error) {
	w := r.Msg.GetPolicy()
	p := Policy{Mode: w.GetMode(), WindowStart: w.GetWindowStart(), WindowMinutes: int(w.GetWindowMinutes()), MirrorURL: strings.TrimRight(strings.TrimSpace(w.GetMirrorUrl()), "/"), Direct: w.GetDirect()}
	callFrom(ctx).note("policy", "mode", p.Mode, "window", p.WindowStart+"+"+itoa(p.WindowMinutes)+"m", "mirror", p.MirrorURL, "direct", strconv.FormatBool(p.Direct))
	if p.Mode != "automatic" && p.Mode != "manual" {
		return nil, codes.New(codes.AccessConfirm, "the mode is automatic or manual")
	}
	if !windowRE.MatchString(p.WindowStart) || p.WindowMinutes < 45 || p.WindowMinutes > 720 {
		return nil, codes.New(codes.AccessConfirm, "the window starts at HH:MM and lasts 45 to 720 minutes")
	}
	if p.MirrorURL != "" && !validMirror(p.MirrorURL) {
		return nil, codes.New(codes.AccessConfirm, "the mirror is an http:// or https:// URL with a host and no credentials or query, or empty for upload only")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(h.s.o.Paths.APIDir(), 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(h.s.ownPath(policyFile), b); err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: update policy set", log.F("mode", p.Mode), log.F("mirror", p.MirrorURL), log.F("direct", p.Direct))
	return connect.NewResponse(&osadminv1.SetUpgradePolicyResponse{}), nil
}

// FetchUpdate downloads a .bin, a base update or a product bundle, from
// the mirror, then the release source when the policy allows direct
// fetches. With neither the box is air-gapped and nothing is fetched.
func (h *upgradeSvc) FetchUpdate(ctx context.Context, r *connect.Request[osadminv1.FetchUpdateRequest]) (*connect.Response[osadminv1.FetchUpdateResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetFileName()
	c.note(name)
	srcs := h.s.sources(name, directPath(name))
	if len(srcs) == 0 {
		return nil, codes.New(codes.UpgradeAirGapped, "no mirror is configured and direct fetches are off, so this box never fetches; upload the .bin instead")
	}
	if !updatepkg.ValidFileName(name) {
		return nil, codes.New(codes.UpgradeUpload, "%q isn't a sneakers-appliance or sneakers-product .bin name", name)
	}
	if err := h.s.reserveReceive(); err != nil {
		return nil, err
	}
	var (
		id, from string
		n        int64
		err      error
	)
	for _, src := range srcs {
		if id, n, err = h.s.fetch(ctx, src, uploadMeta{Name: name, Source: src.name}); err == nil {
			from = src.name
			break
		}
	}
	h.s.releaseReceive()
	h.s.history("fetch", "", c.session.Admin, err, name)
	if err != nil {
		return nil, err
	}
	c.note(name, "upload", id, "bytes", strconv.FormatInt(n, 10), "source", from)
	return connect.NewResponse(&osadminv1.FetchUpdateResponse{UploadId: id, Source: from}), nil
}

// fetch downloads a .bin from src into a new upload. It isn't trusted
// until StageUpdate verifies it, whichever way it came.
func (s *Server) fetch(ctx context.Context, src source, meta uploadMeta) (id string, n int64, err error) {
	started := time.Now()
	resp, peer, err := s.open(ctx, src, ".bin")
	if err == nil {
		id, n, err = s.saveUpload(resp.Body, meta)
		_ = resp.Body.Close()
	}
	s.fetched(ctx, src, ".bin", peer, started, n, err)
	return id, n, err
}

// StageUpdate verifies the .bin's signature, channel and hash, and only
// then decrypts, unpacks and stages it.
func (h *upgradeSvc) StageUpdate(ctx context.Context, r *connect.Request[osadminv1.StageUpdateRequest]) (*connect.Response[osadminv1.StageUpdateResponse], error) {
	c := callFrom(ctx)
	id := r.Msg.GetUploadId()
	c.noteID("uploaded file", "upload", id)
	override := r.Msg.GetOverrideProductRange()
	if override {
		c.noteID("uploaded file", "upload", id, "override", "product-range")
	}
	pkg, removed, err := h.s.stage(ctx, id, override)
	version := ""
	if pkg != nil {
		version = pkg.GetVersion()
		c.noteID("release "+version, "upload", id, "version", version, "kind", pkg.GetKind(), "channel", pkg.GetChannel())
	}
	if len(removed) > 0 {
		c.note(c.target, "removed", strings.Join(removed, ","))
	}
	for _, v := range removed {
		e := c.by("upgrade.remove")
		e.Target = "release " + v
		e.Detail = map[string]string{"version": v, "for": version}
		h.s.write(e, nil)
		h.s.history("remove", v, c.session.Admin, nil, "removed to stage "+version)
	}
	target := osadminv1.UpdateTarget_UPDATE_TARGET_BASE
	if pkg != nil {
		target = pkg.GetTarget()
	}
	h.s.historyFor(target, "stage", version, c.session.Admin, err, id)
	if err != nil {
		h.s.failActive("stage", err)
		return nil, err
	}
	h.s.finishSteps(stepStage)
	out := &osadminv1.StageUpdateResponse{Package: pkg}
	if target != osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT {
		out.Slot = h.s.otherSlot()
	}
	return connect.NewResponse(out), nil
}

// otherSlot is the base slot the box isn't running from, A or B, or ""
// when it doesn't know where it booted from.
func (s *Server) otherSlot() string {
	switch s.o.RootSource {
	case switchroot.LabelRootA:
		return "B"
	case switchroot.LabelRootB:
		return "A"
	}
	return ""
}

// previous is the release kept for a revert and the slot it's in: the one
// the box isn't running from.
func (s *Server) previous(st *initv1.ImageServiceStatusResponse) (version, slot string) {
	if v := st.GetPreviousVersion(); v != "" {
		return v, s.otherSlot()
	}
	return "", ""
}

// stage stages an upload and returns the older releases init removed to
// make room for it. The upload and its unpacked layout are removed once
// init has staged it.
func (s *Server) stage(ctx context.Context, id string, overrideRange bool) (*osadminv1.UpdatePackage, []string, error) {
	if _, err := s.uploadPath(id); err != nil {
		return nil, nil, err
	}
	if err := s.beginStaging(); err != nil {
		return nil, nil, err
	}
	defer s.endStaging()
	pkg, removed, err := s.stageHeld(ctx, id, overrideRange)
	if fb := s.patchFallback(ctx, pkg, err); fb != "" {
		return s.stageHeld(ctx, fb, overrideRange)
	} else if code, ok := patchRefusal(err); ok && pkg.GetFullBin() != "" {
		err = codes.New(code, "%s Upload the full release instead: %s.", strings.TrimSuffix(remoteSentence(err), "."), pkg.GetFullBin())
	}
	return pkg, removed, err
}

// patchRefusal is the code of a patch that didn't fit or didn't rebuild,
// as init or this box refused it.
func patchRefusal(err error) (int, bool) {
	for _, c := range []int{codes.UpgradePatchBase, codes.UpgradePatchResult} {
		if remoteIs(err, c) {
			return c, true
		}
	}
	return 0, false
}

// remoteIs reports whether err carries code, here or as init's Connect
// error, whose message starts with the code's symbol.
func remoteIs(err error, code int) bool {
	if err == nil {
		return false
	}
	if codes.Is(err, code) {
		return true
	}
	ce := new(connect.Error)
	return errors.As(err, &ce) && strings.HasPrefix(ce.Message(), codes.Symbol(code)+" (")
}

// remoteSentence is err's sentence without its code, here or from init.
func remoteSentence(err error) string {
	if ce := new(connect.Error); errors.As(err, &ce) {
		m := ce.Message()
		if i := strings.Index(m, "): "); i >= 0 {
			return m[i+3:]
		}
		return m
	}
	d := describe(err)
	if i := strings.Index(d, "): "); i >= 0 {
		return d[i+3:]
	}
	return d
}

// stageHeld stages the upload id while the stage is held.
func (s *Server) stageHeld(ctx context.Context, id string, overrideRange bool) (*osadminv1.UpdatePackage, []string, error) {
	path, err := s.uploadPath(id)
	if err != nil {
		return nil, nil, err
	}
	// What's staged isn't known until the header is read, so the record
	// starts with the verify step alone.
	s.beginProgress("stage", osadminv1.UpdateTarget_UPDATE_TARGET_UNSPECIFIED, "", "")
	s.setStep(stepVerify, "")
	f, err := os.Open(path) // #nosec G304 -- an upload this box made
	if err != nil {
		return nil, nil, codes.Wrap(codes.UpgradeUpload, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, codes.Wrap(codes.UpgradeUpload, err)
	}
	p, err := updatepkg.Read(f, st.Size())
	if err != nil {
		s.reject(path, err)
		return nil, nil, err
	}
	if p.Header.IsProduct() {
		s.beginProgress("stage", osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "", "")
	} else {
		s.beginProgress("stage", osadminv1.UpdateTarget_UPDATE_TARGET_BASE, "", s.otherSlot())
	}
	s.setStep(stepVerify, "")
	if err := p.Verify(s.o.Upgrade.ReleaseKeyPEM, s.o.Upgrade.Channel); err != nil {
		s.reject(path, err)
		return nil, nil, err
	}
	h := p.Header
	pkg := &osadminv1.UpdatePackage{UploadId: id, Version: h.Version, Arch: h.Arch, Kind: string(h.Kind), Bases: h.Bases, Channel: h.Channel, Sha256: h.Payload.SHA256, Size: h.Payload.Size,
		Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE, MinBase: h.MinBase, MaxBase: h.MaxBase, Source: s.uploadSource(id)}
	if h.Target != nil {
		pkg.FullBin = h.Target.FullBin
	}
	s.setVersion(h.Version)
	if h.IsProduct() {
		pkg.Target = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
		return pkg, nil, s.stageProduct(ctx, path, p)
	}
	img, err := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil {
		return pkg, nil, err
	}
	if err := h.AppliesTo(img.Msg.GetRunningVersion()); err != nil {
		s.reject(path, err)
		return pkg, nil, err
	}
	var patch *initv1.StagePatch
	if h.Kind == updatepkg.KindPatch {
		spec, err := basepatch.SpecOf(h)
		if err != nil {
			s.reject(path, err)
			return pkg, nil, err
		}
		patch = &initv1.StagePatch{BaseVersion: spec.BaseVersion, BaseRootSha256: spec.BaseRootSHA256, BaseRootSize: spec.BaseRootSize, BaseUkiSha256: spec.BaseUKISHA256,
			RootSha256: spec.RootSHA256, UkiSha256: spec.UKISHA256}
	}
	if err := s.fitsInstalledProduct(h.Version, overrideRange); err != nil {
		return pkg, nil, err
	}
	s.o.Logger.Info("osadmin: update verified; unpacking", log.F("upload", id), log.F("version", h.Version), log.F("kind", string(h.Kind)))
	s.setStep(stepStage, "Decrypting and unpacking the release.")
	key, err := s.o.Upgrade.UpdateKey()
	if err != nil {
		return pkg, nil, codes.Wrap(codes.UpgradeDecrypt, err)
	}
	dir := strings.TrimSuffix(path, ".bin") + ".d"
	if err := os.RemoveAll(dir); err != nil {
		return pkg, nil, err
	}
	// The layout is needed only while init stages it; a retry unpacks the
	// upload again.
	defer s.removeUpload(dir)
	if err := unpack(p, key, dir); err != nil {
		return pkg, nil, err
	}
	s.setStep(stepStage, "Writing the release into "+slotName(s.otherSlot())+".")
	if patch != nil {
		s.setStep(stepStage, "Rebuilding the release from the patch and "+h.Base.Version+", then writing it into "+slotName(s.otherSlot())+".")
	}
	res, err := s.o.Image.Stage(ctx, connect.NewRequest(&initv1.StageRequest{Reference: dir, Patch: patch}))
	if err != nil {
		if patch != nil {
			s.removeUpload(path)
		}
		return pkg, nil, err
	}
	s.removeUpload(path)
	s.o.Logger.Info("osadmin: update staged", log.F("version", h.Version), log.F("removed", strings.Join(res.Msg.GetRemovedVersions(), ",")))
	return pkg, res.Msg.GetRemovedVersions(), nil
}

// patchFallback takes the full .bin of a patch's release when the patch
// didn't fit the running base or didn't rebuild (spec 5, Section 2.10.3):
// for a patch fetched from a source, it fetches the full file the signed
// header names from the same sources and returns its upload id, with an
// audit entry; "" when there's nothing to fall back to. An uploaded patch
// isn't followed by a fetch: the refusal names the full file instead.
func (s *Server) patchFallback(ctx context.Context, pkg *osadminv1.UpdatePackage, err error) string {
	code, ok := patchRefusal(err)
	if !ok || pkg.GetKind() != string(updatepkg.KindPatch) {
		return ""
	}
	full := pkg.GetFullBin()
	c := callFrom(ctx)
	e := c.by("upgrade.patch-fallback")
	e.Target = "release " + pkg.GetVersion()
	e.Detail = map[string]string{"version": pkg.GetVersion(), "reason": codes.Symbol(code), "full": full, "source": pkg.GetSource()}
	if full == "" || pkg.GetSource() == "" || pkg.GetSource() == "upload" {
		s.o.Logger.Warn("osadmin: a patch didn't apply; upload the full .bin", log.F("version", pkg.GetVersion()), log.F("full", full), log.F("error", describe(err)))
		return ""
	}
	s.o.Logger.Warn("osadmin: a patch didn't apply; fetching the full .bin", log.F("version", pkg.GetVersion()), log.F("full", full), log.F("reason", codes.Symbol(code)))
	var id string
	var ferr error
	for _, src := range s.sources(full, directPath(full)) {
		if id, _, ferr = s.fetch(ctx, src, uploadMeta{Name: full, Source: src.name}); ferr == nil {
			break
		}
	}
	if len(s.sources(full, directPath(full))) == 0 {
		ferr = codes.New(codes.UpgradeAirGapped, "no source to fetch %s from", full)
	}
	s.write(e, ferr)
	s.history("fallback", pkg.GetVersion(), c.session.Admin, ferr, full)
	if ferr != nil {
		s.o.Logger.Warn("osadmin: the full .bin wasn't fetched", log.F("full", full), log.F("error", describe(ferr)))
		return ""
	}
	return id
}

// fitsInstalledProduct refuses a base release outside the installed
// product bundle's base range, unless the owner overrides it. The upload
// is kept, so it can be staged again with the override. A product sealed
// before the range existed isn't checked, with a note in the log.
func (s *Server) fitsInstalledProduct(version string, override bool) error {
	inst, ok := s.slots().Installed()
	if !ok {
		return nil
	}
	if !inst.HasRange() {
		s.o.Logger.Info("osadmin: the installed product names no base range; the base release isn't checked against it", log.F("product", inst.Version), log.F("base", version))
		return nil
	}
	if inst.InRange(version) {
		return nil
	}
	if override {
		s.o.Logger.Warn("osadmin: a base release outside the installed product's range stages under an owner's override", log.F("product", inst.Version), log.F("range", inst.RangeText()), log.F("base", version))
		return nil
	}
	s.o.Logger.Warn("osadmin: a base release is outside the installed product's range", log.F("product", inst.Version), log.F("range", inst.RangeText()), log.F("base", version))
	return codes.New(codes.UpgradeProductBase, "the installed product %s needs base %s; %s is outside it. Install a product bundle that fits %s first, or stage it with the override", inst.Version, inst.RangeText(), version, version)
}

// slotName is a base slot as a sentence says it.
func slotName(slot string) string {
	if slot == "" {
		return "the other slot"
	}
	return "slot " + slot
}

// removeUpload removes an upload's .bin (with its details) or its
// unpacked layout once it's no longer needed.
func (s *Server) removeUpload(p string) {
	if strings.HasSuffix(p, ".bin") {
		_ = os.Remove(strings.TrimSuffix(p, ".bin") + ".json")
	}
	if err := os.RemoveAll(p); err != nil {
		s.o.Logger.Error(err, "osadmin: a staged upload wasn't removed", log.F("file", filepath.Base(p)))
		return
	}
	s.o.Logger.Debug("osadmin: removed a staged upload", log.F("file", filepath.Base(p)))
}

// unpack decrypts the payload into a pipe and untars it into dir.
func unpack(p *updatepkg.Package, key age.Identity, dir string) error {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- updatepkg.Untar(pr, dir) }()
	err := p.Decrypt(key, pw)
	_ = pw.CloseWithError(err)
	uerr := <-done
	_ = pr.Close()
	if err != nil {
		return err
	}
	if uerr != nil {
		return codes.New(codes.UpgradeFormat, "the payload doesn't unpack: %v", uerr)
	}
	return nil
}

// reject removes an upload that failed verification; it is never
// unpacked.
func (s *Server) reject(path string, err error) {
	s.o.Logger.Warn("osadmin: update refused before unpacking", log.F("file", filepath.Base(path)), log.F("error", describe(err)))
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		s.o.Logger.Error(rerr, "osadmin: refused upload not removed")
	}
	_ = os.Remove(strings.TrimSuffix(path, ".bin") + ".json")
}

// by is who an update action is for, as the start of an audit entry.
func (c *call) by(action string) osaudit.Entry {
	return osaudit.Entry{Actor: c.session.Admin, Source: c.source, Action: action, Detail: c.detail}
}

// DiscardUpdate drops a held upload by id, or unstages the staged base
// release or product bundle. Nothing is dropped while a stage runs.
func (h *upgradeSvc) DiscardUpdate(ctx context.Context, r *connect.Request[osadminv1.DiscardUpdateRequest]) (*connect.Response[osadminv1.DiscardUpdateResponse], error) {
	c := callFrom(ctx)
	id, target := r.Msg.GetUploadId(), r.Msg.GetTarget()
	if id != "" {
		c.noteID("uploaded file", "upload", id)
	} else {
		c.note(targetName(target))
	}
	if h.s.isStaging() {
		return nil, codes.New(codes.UpgradeBusy, "a stage is under way; wait for it to finish, then cancel")
	}
	if id != "" {
		if !uploadIDRE.MatchString(id) {
			return nil, codes.New(codes.UpgradeUpload, "%q isn't an upload this box made", id)
		}
		if !h.s.dropUpload(id) {
			return nil, codes.New(codes.UpgradeUpload, "there is no upload %s", id)
		}
		h.s.history("discard", "", c.session.Admin, nil, "upload "+id)
		h.s.o.Logger.Info("osadmin: upload discarded", log.F("upload", id), log.F("by", c.session.Admin))
		return connect.NewResponse(&osadminv1.DiscardUpdateResponse{}), nil
	}
	var (
		v   string
		err error
	)
	switch target {
	case osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT:
		v, err = h.s.slots().Unstage()
	case osadminv1.UpdateTarget_UPDATE_TARGET_BASE:
		var res *connect.Response[initv1.UnstageResponse]
		if res, err = h.s.o.Image.Unstage(ctx, connect.NewRequest(&initv1.UnstageRequest{})); err == nil {
			v = res.Msg.GetVersion()
		}
	default:
		return nil, codes.New(codes.AccessConfirm, "name the upload to drop, or the target (base or product) to unstage")
	}
	if v != "" {
		c.note("release "+v, "version", v, "target", targetName(target))
	}
	if err != nil {
		return nil, err
	}
	h.s.historyFor(target, "discard", v, c.session.Admin, nil, "unstaged")
	h.s.o.Logger.Info("osadmin: staged release discarded", log.F("target", targetName(target)), log.F("version", v), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.DiscardUpdateResponse{Version: v}), nil
}

func (h *upgradeSvc) ApplyUpdate(ctx context.Context, r *connect.Request[osadminv1.ApplyUpdateRequest]) (*connect.Response[osadminv1.ApplyUpdateResponse], error) {
	c := callFrom(ctx)
	apply, what := h.s.apply, "box"
	if r.Msg.GetTarget() == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT {
		apply, what = h.s.applyProduct, "product"
	}
	v, overrode, err := apply(ctx, c.by("upgrade.apply"), r.Msg.GetElevationOverride())
	c.note(what, "version", v)
	if overrode != "" {
		c.note(what, "overrode", overrode)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.ApplyUpdateResponse{}), nil
}

// apply boots the staged release: init activates it and reboots. o is an
// owner's override of an open elevated shell, or nil.
func (s *Server) apply(ctx context.Context, by osaudit.Entry, o *osadminv1.ElevationOverride) (string, string, error) {
	actor := by.Actor
	st, err := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil {
		return "", "", err
	}
	v := st.Msg.GetStagedVersion()
	if v == "" {
		err = codes.New(codes.UpgradeNotStaged, "no release is staged; upload or fetch one and stage it first")
	}
	overrode := ""
	if err == nil {
		overrode, err = s.beginMaintenance(ctx, "update applies", by, o)
	}
	if err == nil {
		s.continueApply(osadminv1.UpdateTarget_UPDATE_TARGET_BASE, v, s.otherSlot())
		err = s.rebootInto(ctx, v, func() error {
			_, err := s.o.Image.Activate(ctx, connect.NewRequest(&initv1.ActivateRequest{}))
			return err
		})
	}
	if err != nil {
		s.endMaintenance()
	}
	s.history("apply", v, actor, err, overrideDetail(overrode))
	s.o.Logger.Info("osadmin: apply", log.F("version", v), log.F("by", actor), log.F("ok", err == nil))
	return v, overrode, err
}

// MarkGood commits the release the box booted, the upgrades design's
// commit step: once setup is done and init and netd answer, init drops the
// running entry's boot counter, so boot counting no longer falls back from
// it. Until platformd's health gate exists those are the health checks; a
// box with no product depends on nothing else. It waits while an apply or
// revert is under way: a revert has marked the running release bad, and
// marking it good before the reboot would undo that. The command calls it
// at start and each minute until it succeeds.
func (s *Server) MarkGood(ctx context.Context) error {
	if s.Maintenance() {
		return errors.New("osadmin: an update is being applied or reverted; the release isn't marked good")
	}
	// After an apply's or a revert's reboot, the update's last steps are
	// this loop's: checking health, then marking good.
	track := s.afterReboot(ctx)
	health := func(why string) {
		if track {
			s.setStep(stepHealth, why)
		}
	}
	if !s.SetupDone() {
		health("Waiting for setup to finish.")
		return errors.New("osadmin: setup isn't done; the release isn't marked good yet")
	}
	if _, err := s.o.KeyCustody.Protection(ctx, connect.NewRequest(&initv1.ProtectionRequest{})); err != nil {
		s.o.Logger.Warn("osadmin: init doesn't answer; the release isn't marked good yet", log.F("error", err.Error()))
		health("Waiting for init to answer: " + err.Error())
		return err
	}
	if _, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{})); err != nil {
		s.o.Logger.Warn("osadmin: netd doesn't answer; the release isn't marked good yet", log.F("error", err.Error()))
		health("Waiting for netd to answer: " + err.Error())
		return err
	}
	if track {
		s.setStep(stepMarkGood, "")
	}
	if _, err := s.o.Image.MarkGood(ctx, connect.NewRequest(&initv1.MarkGoodRequest{})); err != nil {
		s.o.Logger.Error(err, "osadmin: the release wasn't marked good")
		if track {
			s.setStep(stepMarkGood, "Not marked good yet, trying again in a minute: "+describe(err))
		}
		return err
	}
	if track {
		s.finishSteps(stepMarkGood)
	}
	s.o.Logger.Info("osadmin: the running release is marked good", log.F("version", release.Version))
	return nil
}

// afterReboot reports whether the update record waits on this boot's
// checks: a base apply or revert past its switch. When the box came back
// on another release than the one it rebooted into, that step fails
// instead, naming both: boot counting went back by itself.
func (s *Server) afterReboot(ctx context.Context) bool {
	r := s.progressSnapshot()
	if r == nil || r.Target == "product" {
		return false
	}
	switch r.active() {
	case stepReboot, stepHealth, stepMarkGood:
	default:
		return false
	}
	if r.active() == stepReboot && s.sameBoot(r) {
		// osadmin restarted, the box didn't: the reboot is still to come,
		// and the watchdog gives up on it if it never does.
		return false
	}
	st, err := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil {
		s.setStep(stepHealth, "Waiting for init to answer: "+err.Error())
		return true
	}
	running := st.Msg.GetRunningVersion()
	if running == r.Version {
		if r.active() == stepReboot {
			s.setStep(stepHealth, "")
		}
		return true
	}
	why := "The box came back on " + running + ", not " + r.Version + "."
	if st.Msg.GetFailedVersion() == r.Version {
		why = r.Version + " didn't come up healthy, so the box went back to " + running + " by itself."
	}
	s.setStep(stepHealth, "")
	s.progress.mu.Lock()
	s.failStepLocked(stepHealth, why, "")
	s.progress.mu.Unlock()
	return false
}

// RebootBound is how long the reboot step of an apply or revert may stay
// active on the boot it started on before the watchdog fails it.
const RebootBound = 10 * time.Minute

// sameBoot reports whether r's reboot step started on the running boot.
func (s *Server) sameBoot(r *progressRecord) bool {
	return s.o.BootID != "" && r.BootID == s.o.BootID
}

// RebootWatchdog fails the reboot step of an apply or revert that has
// waited RebootBound on the boot it started on: init took the reboot but
// the box never went down. The step fails with UPGRADE_NO_REBOOT, so the
// console and :8443 leave the maintenance screen, and maintenance ends so
// Apply is offered again. The boot entry the switch made is left as it
// is. The command calls it each minute.
func (s *Server) RebootWatchdog() {
	s.progress.mu.Lock()
	s.loadProgress()
	r := s.progress.rec
	if r == nil || r.active() != stepReboot || !s.sameBoot(r) {
		s.progress.mu.Unlock()
		return
	}
	waited := s.o.Clock.Now().Sub(r.RebootAt)
	if waited < RebootBound {
		s.progress.mu.Unlock()
		return
	}
	action, version := r.Action, r.Version
	err := codes.New(codes.UpgradeNoReboot, "the box didn't reboot into %s within %d minutes", version, int(RebootBound.Minutes()))
	why := "The box didn't reboot into " + version + " within " + strconv.Itoa(int(RebootBound.Minutes())) + " minutes. Apply again, or restart the box."
	s.failStepLocked(stepReboot, why, codes.Symbol(codes.UpgradeNoReboot))
	s.progress.mu.Unlock()
	s.o.Logger.Warn("osadmin: the reboot never came; the update step failed", log.F("action", action), log.F("version", version), log.F("waited", waited.Round(time.Second).String()))
	s.endMaintenance()
	s.history(action, version, "osadmin", err, "no reboot after "+waited.Round(time.Second).String())
	s.write(osaudit.Entry{Actor: "osadmin", Action: "upgrade.reboot-missed", Target: "box", Detail: map[string]string{"version": version, "action": action, "waited": waited.Round(time.Second).String()}}, err)
	s.consoleChanged()
}

// rebootInto runs an apply's or a revert's switch, then the reboot into
// version, each as its step: the reboot step stays active until the
// booted release's MarkGood loop takes over.
func (s *Server) rebootInto(ctx context.Context, version string, switchSlots func() error) error {
	s.setStep(stepSwitch, "")
	if err := switchSlots(); err != nil {
		s.failStep(stepSwitch, err)
		return err
	}
	s.setStep(stepReboot, "The box restarts into "+version+".")
	if _, err := s.o.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{})); err != nil {
		s.failStep(stepReboot, err)
		return err
	}
	return nil
}

func overrideDetail(id string) string {
	if id == "" {
		return ""
	}
	return "ended elevated shell " + id
}

func (h *upgradeSvc) RevertUpdate(ctx context.Context, r *connect.Request[osadminv1.RevertUpdateRequest]) (*connect.Response[osadminv1.RevertUpdateResponse], error) {
	c := callFrom(ctx)
	if r.Msg.GetTarget() == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT {
		c.note("product")
		v, overrode, err := h.s.revertProduct(ctx, c.by("upgrade.revert"), r.Msg.GetElevationOverride())
		c.note("product", "version", v)
		if overrode != "" {
			c.note("product", "overrode", overrode)
		}
		if err != nil {
			return nil, err
		}
		return connect.NewResponse(&osadminv1.RevertUpdateResponse{}), nil
	}
	c.note("box")
	overrode, err := h.s.beginMaintenance(ctx, "update reverts", c.by("upgrade.revert"), r.Msg.GetElevationOverride())
	if overrode != "" {
		c.note("box", "overrode", overrode)
	}
	if err == nil {
		back := ""
		if st, serr := h.s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{})); serr == nil {
			back = st.Msg.GetPreviousVersion()
		}
		h.s.beginProgress("revert", osadminv1.UpdateTarget_UPDATE_TARGET_BASE, back, "")
		err = h.s.rebootInto(ctx, back, func() error {
			_, err := h.s.o.Image.Rollback(ctx, connect.NewRequest(&initv1.RollbackRequest{By: c.session.Admin}))
			return err
		})
	}
	if err != nil {
		h.s.endMaintenance()
	}
	h.s.history("revert", "", c.session.Admin, err, overrideDetail(overrode))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RevertUpdateResponse{}), nil
}

// UpgradeWindowTick applies a staged release when the policy is
// automatic, now is inside the window, and the window hasn't applied one
// today. The command calls it every minute.
func (s *Server) UpgradeWindowTick(ctx context.Context) {
	p := s.policy()
	if p.Mode != "automatic" {
		return
	}
	now := s.o.Clock.Now().Local()
	start, err := time.ParseInLocation("15:04", p.WindowStart, now.Location())
	if err != nil {
		return
	}
	open := time.Date(now.Year(), now.Month(), now.Day(), start.Hour(), start.Minute(), 0, 0, now.Location())
	if now.Before(open) || !now.Before(open.Add(time.Duration(p.WindowMinutes)*time.Minute)) {
		return
	}
	day := open.Format(time.DateOnly)
	if s.o.Elevation != nil && s.o.Elevation.Active() {
		s.o.Logger.Info("osadmin: the update window waits for an active elevated session to end")
		return
	}
	s.productWindow(ctx, day)
	s.upgrades.mu.Lock()
	if s.upgrades.lastWindow == day {
		s.upgrades.mu.Unlock()
		return
	}
	s.upgrades.mu.Unlock()
	st, err := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetStagedVersion() == "" {
		return
	}
	s.upgrades.mu.Lock()
	s.upgrades.lastWindow = day
	s.upgrades.mu.Unlock()
	v, _, err := s.apply(ctx, osaudit.Entry{Actor: "window", Action: "upgrade.apply"}, nil)
	s.write(osaudit.Entry{Actor: "window", Action: "upgrade.apply", Target: "box", Detail: map[string]string{"version": v, "surface": "window"}}, err)
}

// productWindow applies a staged product bundle once per window, before a
// staged base release (whose apply reboots).
func (s *Server) productWindow(ctx context.Context, day string) {
	s.upgrades.mu.Lock()
	if s.upgrades.lastProductWindow == day || s.slots().Status().Staged == "" {
		s.upgrades.mu.Unlock()
		return
	}
	s.upgrades.lastProductWindow = day
	s.upgrades.mu.Unlock()
	v, _, err := s.applyProduct(ctx, osaudit.Entry{Actor: "window", Action: "upgrade.apply"}, nil)
	s.write(osaudit.Entry{Actor: "window", Action: "upgrade.apply", Target: "product", Detail: map[string]string{"version": v, "surface": "window"}}, err)
}
