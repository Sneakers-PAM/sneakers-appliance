// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
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
	binNameRE  = regexp.MustCompile(`^sneakers-(appliance|product)-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?-(amd64|arm64)(-LAB)?\.bin$`)
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
	// HTTPClient fetches from the mirror; nil uses a client with the
	// environment's proxy.
	HTTPClient *http.Client
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
	e.Action, e.Target = "elevation.terminate", r.ID
	e.Detail = map[string]string{"admin": r.Admin, "reason": reason, "for": by.Action}
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

// saveUpload copies r (at most MaxUpload bytes) into a new upload and
// returns its id.
func (s *Server) saveUpload(r io.Reader) (string, int64, error) {
	dir := filepath.Join(s.o.Paths.APIDir(), uploadsDir)
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
		if _, coded := codes.Of(err); coded {
			return "", 0, err
		}
		return "", 0, codes.Wrap(codes.UpgradeUpload, err)
	}
	if err := os.Rename(final+".tmp", final); err != nil {
		return "", 0, fmt.Errorf("upload: %w", err)
	}
	return id, n, nil
}

// handleUpload is POST /upload: the .bin as the body, the session cookie
// and the CSRF header.
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
	id, n, err := s.saveUpload(http.MaxBytesReader(w, r.Body, MaxUpload+1))
	entry.Target = id
	entry.Detail = map[string]string{"bytes": strconv.FormatInt(n, 10)}
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
		Product: h.s.productSlots(ctx), DirectAvailable: direct}
	if st, err := h.s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{})); err == nil {
		out.RunningVersion, out.StagedVersion, out.FailedVersion = st.Msg.GetRunningVersion(), st.Msg.GetStagedVersion(), st.Msg.GetFailedVersion()
		out.RevertedVersion, out.RevertedBy, out.RevertedAt = st.Msg.GetRevertedVersion(), st.Msg.GetRevertedBy(), st.Msg.GetRevertedAt()
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
	if p.MirrorURL != "" {
		u, err := url.Parse(p.MirrorURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return nil, codes.New(codes.AccessConfirm, "the mirror is an https:// URL without credentials, or empty for upload only")
		}
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
	if !binNameRE.MatchString(name) {
		return nil, codes.New(codes.UpgradeUpload, "%q isn't a sneakers-appliance or sneakers-product .bin name", name)
	}
	var (
		id, from string
		n        int64
		err      error
	)
	for _, src := range srcs {
		if id, n, err = h.s.fetch(ctx, src.url); err == nil {
			from = src.name
			break
		}
	}
	h.s.history("fetch", "", c.session.Admin, err, name)
	if err != nil {
		return nil, err
	}
	c.note(name, "upload", id, "bytes", strconv.FormatInt(n, 10), "source", from)
	return connect.NewResponse(&osadminv1.FetchUpdateResponse{UploadId: id, Source: from}), nil
}

func (s *Server) fetch(ctx context.Context, target string) (string, int64, error) {
	hc := s.httpClient()
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", 0, codes.Wrap(codes.UpgradeUpload, err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		s.o.Logger.Warn("osadmin: mirror fetch failed", log.F("target", target), log.F("error", err.Error()))
		return "", 0, codes.New(codes.UpgradeUpload, "the mirror didn't answer: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", 0, codes.New(codes.UpgradeUpload, "the mirror answered %s", resp.Status)
	}
	id, n, err := s.saveUpload(resp.Body)
	s.o.Logger.Info("osadmin: mirror fetch", log.F("target", target), log.F("bytes", n), log.F("ms", time.Since(started).Milliseconds()), log.F("ok", err == nil))
	return id, n, err
}

// StageUpdate verifies the .bin's signature, channel and hash, and only
// then decrypts, unpacks and stages it.
func (h *upgradeSvc) StageUpdate(ctx context.Context, r *connect.Request[osadminv1.StageUpdateRequest]) (*connect.Response[osadminv1.StageUpdateResponse], error) {
	c := callFrom(ctx)
	id := r.Msg.GetUploadId()
	c.note(id)
	pkg, err := h.s.stage(ctx, id)
	version := ""
	if pkg != nil {
		version = pkg.GetVersion()
		c.note(id, "version", version, "kind", pkg.GetKind(), "channel", pkg.GetChannel())
	}
	target := osadminv1.UpdateTarget_UPDATE_TARGET_BASE
	if pkg != nil {
		target = pkg.GetTarget()
	}
	h.s.historyFor(target, "stage", version, c.session.Admin, err, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.StageUpdateResponse{Package: pkg}), nil
}

func (s *Server) stage(ctx context.Context, id string) (*osadminv1.UpdatePackage, error) {
	path, err := s.uploadPath(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- an upload this box made
	if err != nil {
		return nil, codes.Wrap(codes.UpgradeUpload, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, codes.Wrap(codes.UpgradeUpload, err)
	}
	p, err := updatepkg.Read(f, st.Size())
	if err != nil {
		s.reject(path, err)
		return nil, err
	}
	if err := p.Verify(s.o.Upgrade.ReleaseKeyPEM, s.o.Upgrade.Channel); err != nil {
		s.reject(path, err)
		return nil, err
	}
	h := p.Header
	pkg := &osadminv1.UpdatePackage{UploadId: id, Version: h.Version, Arch: h.Arch, Kind: string(h.Kind), Bases: h.Bases, Channel: h.Channel, Sha256: h.Payload.SHA256, Size: h.Payload.Size,
		Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE}
	if h.IsProduct() {
		pkg.Target = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
		return pkg, s.stageProduct(ctx, path, p)
	}
	img, err := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil {
		return pkg, err
	}
	if err := h.AppliesTo(img.Msg.GetRunningVersion()); err != nil {
		s.reject(path, err)
		return pkg, err
	}
	s.o.Logger.Info("osadmin: update verified; unpacking", log.F("upload", id), log.F("version", h.Version), log.F("kind", string(h.Kind)))
	key, err := s.o.Upgrade.UpdateKey()
	if err != nil {
		return pkg, codes.Wrap(codes.UpgradeDecrypt, err)
	}
	dir := strings.TrimSuffix(path, ".bin") + ".d"
	if err := os.RemoveAll(dir); err != nil {
		return pkg, err
	}
	if err := unpack(p, key, dir); err != nil {
		_ = os.RemoveAll(dir)
		return pkg, err
	}
	if _, err := s.o.Image.Stage(ctx, connect.NewRequest(&initv1.StageRequest{Reference: dir})); err != nil {
		return pkg, err
	}
	s.o.Logger.Info("osadmin: update staged", log.F("version", h.Version))
	return pkg, nil
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
}

// by is who an update action is for, as the start of an audit entry.
func (c *call) by(action string) osaudit.Entry {
	return osaudit.Entry{Actor: c.session.Admin, Source: c.source, Action: action, Detail: c.detail}
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
		_, err = s.o.Image.Activate(ctx, connect.NewRequest(&initv1.ActivateRequest{}))
	}
	if err == nil {
		_, err = s.o.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{}))
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
	if !s.SetupDone() {
		return errors.New("osadmin: setup isn't done; the release isn't marked good yet")
	}
	if s.Maintenance() {
		return errors.New("osadmin: an update is being applied or reverted; the release isn't marked good")
	}
	if _, err := s.o.KeyCustody.Protection(ctx, connect.NewRequest(&initv1.ProtectionRequest{})); err != nil {
		s.o.Logger.Warn("osadmin: init doesn't answer; the release isn't marked good yet", log.F("error", err.Error()))
		return err
	}
	if _, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{})); err != nil {
		s.o.Logger.Warn("osadmin: netd doesn't answer; the release isn't marked good yet", log.F("error", err.Error()))
		return err
	}
	if _, err := s.o.Image.MarkGood(ctx, connect.NewRequest(&initv1.MarkGoodRequest{})); err != nil {
		s.o.Logger.Error(err, "osadmin: the release wasn't marked good")
		return err
	}
	s.o.Logger.Info("osadmin: the running release is marked good", log.F("version", release.Version))
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
		_, err = h.s.o.Image.Rollback(ctx, connect.NewRequest(&initv1.RollbackRequest{By: c.session.Admin}))
	}
	if err == nil {
		_, err = h.s.o.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{}))
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
