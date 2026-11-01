// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"archive/zip"
	"compress/flate"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/encoding/protojson"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/supportbundle"
)

// WriteSupportBundle writes the support bundle to w for a closed-shell
// login (docs/support-bundle.md). It's audited as support.bundle.
func (s *Server) WriteSupportBundle(ctx context.Context, w io.Writer, l Local, form supportbundle.Form) error {
	surface := SurfaceSSH
	if l.Admin == "" {
		surface = osaudit.SurfaceConsole
	}
	entry := osaudit.Entry{Actor: l.Admin, KeyFP: l.KeyFP, Source: l.Source, Action: "support.bundle", Target: "support bundle", Detail: map[string]string{"surface": surface}}
	if entry.Actor == "" {
		entry.Actor = osaudit.SurfaceConsole
	}
	return s.writeBundle(ctx, w, form, entry)
}

// writeBundle runs one bundle at a time, so a second one can't load a box
// that's already in trouble, and audits how it went.
func (s *Server) writeBundle(ctx context.Context, w io.Writer, form supportbundle.Form, entry osaudit.Entry) error {
	entry.Detail["form"] = string(form)
	if s.o.Support == nil {
		err := codes.New(codes.NotAvailable, "the support bundle isn't available on this box")
		s.write(entry, err)
		return err
	}
	if !s.bundleMu.TryLock() {
		err := codes.New(codes.NotAvailable, "a support bundle is being made; try again when it's done")
		s.write(entry, err)
		return err
	}
	defer s.bundleMu.Unlock()

	s.o.Logger.Info("osadmin: a support bundle starts", log.F("admin", entry.Actor), log.F("form", string(form)), log.F("surface", entry.Detail["surface"]))
	cfg := *s.o.Support
	cfg.Progress = s.ownPath(progressFile)
	if cfg.Status == nil {
		cfg.Status = s.bundleStatus
	}
	if cfg.Audit == nil {
		cfg.Audit = s.bundleAudit
	}
	opts := supportbundle.Options{Form: form, Box: s.boxName(ctx), Version: release.Version}
	sections := cfg.Base(form)
	if info := productinfo.Installed(s.slots().Dir); info.Present() {
		opts.Product = info.Title
	}
	if cur := s.slots().Current(); cur != "" {
		spec, err := productspec.Load(cur)
		if err != nil {
			s.o.Logger.Warn("osadmin: the bundle leaves out the product's sections: its product.yaml doesn't read", log.F("error", err.Error()))
		}
		sections = append(sections, cfg.Product(spec, form)...)
		if opts.Product == "" {
			opts.Product = "the installed product"
		}
	}
	if s.o.SupportSecrets != nil {
		known, err := s.o.SupportSecrets()
		if err != nil {
			s.o.Logger.Warn("osadmin: the bundle runs on its patterns alone: the box's secrets don't read", log.F("error", err.Error()))
		}
		opts.Known = known
	}
	report, err := supportbundle.Write(ctx, w, opts, sections)
	entry.Detail["bytes"] = strconv.FormatInt(report.Bytes, 10)
	entry.Detail["sections"] = strconv.Itoa(report.Sections)
	entry.Detail["failed"] = strconv.Itoa(report.Failed)
	entry.Detail["truncated"] = strconv.Itoa(report.Truncated)
	s.write(entry, err)
	if err != nil {
		s.o.Logger.Warn("osadmin: a support bundle stopped early", log.F("error", err.Error()), log.F("bytes", report.Bytes))
		return err
	}
	s.o.Logger.Info("osadmin: a support bundle is done", log.F("bytes", report.Bytes), log.F("sections", report.Sections), log.F("failed", report.Failed), log.F("truncated", report.Truncated))
	return nil
}

// boxName heads the file and names the download; a netd that's down, the
// sort of thing a bundle is made for, leaves it out.
func (s *Server) boxName(ctx context.Context) string {
	if s.o.Network == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		s.o.Logger.Warn("osadmin: the bundle has no host name: netd didn't answer", log.F("error", err.Error()))
		return ""
	}
	return st.Msg.GetHostname()
}

// bundleStatus writes the Status the box's page shows, as JSON.
func (s *Server) bundleStatus(ctx context.Context, w io.Writer) error {
	st, err := (&status{s: s}).GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		return err
	}
	b, err := protojson.MarshalOptions{Multiline: true}.Marshal(st.Msg)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// bundleAudit writes the OS audit log's newest n entries, as written.
func (s *Server) bundleAudit(_ context.Context, w io.Writer, n int) error {
	all, err := s.o.Audit.Entries()
	if err != nil {
		return err
	}
	for _, e := range all[max(0, len(all)-n):] {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
			return err
		}
	}
	return nil
}

// bundleArchive is the :8443 download's zip, holding the bundle's text as
// one entry. Nothing of it is written until the bundle's first byte, so a
// refused bundle still leaves the response free for a plain 503.
type bundleArchive struct {
	w       http.ResponseWriter
	header  zip.FileHeader
	zip     *zip.Writer
	deflate *flate.Writer
	entry   io.Writer
}

func (a *bundleArchive) Write(p []byte) (int, error) {
	if a.zip == nil {
		a.zip = zip.NewWriter(a.w)
		a.zip.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
			var err error
			a.deflate, err = flate.NewWriter(out, flate.BestCompression)
			return a.deflate, err
		})
		var err error
		if a.entry, err = a.zip.CreateHeader(&a.header); err != nil {
			return 0, err
		}
	}
	return a.entry.Write(p)
}

// Flush passes the bundle's flush at each section's end through deflate
// and on to the client. Deflate would otherwise hold megabytes back, and
// the forwarder gives up on an answer that hasn't started in two minutes.
// A failure here comes back from the next Write.
func (a *bundleArchive) Flush() {
	if a.zip == nil {
		return
	}
	if a.deflate.Flush() != nil || a.zip.Flush() != nil {
		return
	}
	_ = http.NewResponseController(a.w).Flush()
}

// started says the response has been written to.
func (a *bundleArchive) started() bool { return a.zip != nil }

// Close ends the entry and writes the zip's directory, which is what makes
// the file open at all.
func (a *bundleArchive) Close() error {
	if a.zip == nil {
		return nil
	}
	return a.zip.Close()
}

// exportSupportBundle streams the full bundle as a zip of its one text
// file, to any signed-in admin. A file left on a laptop can't say more
// than the box's own logs say, and they're redacted, so it asks no step-up
// and isn't encrypted.
func (s *Server) exportSupportBundle(w http.ResponseWriter, r *http.Request) {
	entry := osaudit.Entry{Source: hostOf(r.RemoteAddr), Action: "support.bundle", Target: "support bundle", Detail: map[string]string{"surface": osaudit.SurfaceAdmin}}
	sess, err := s.session(r.Header)
	if err == nil {
		_, err = s.liveRole(sess)
	}
	entry.Actor = sess.Admin
	if err != nil {
		entry.Detail["form"] = string(supportbundle.Full)
		s.write(entry, err)
		http.Error(w, codes.Describe(err), http.StatusUnauthorized)
		return
	}
	now := s.o.Clock.Now().UTC()
	name := "support-bundle-" + firstLabel(s.boxName(r.Context())) + "-" + now.Format("20060102T150405Z")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.zip"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	archive := &bundleArchive{w: w, header: zip.FileHeader{Name: name + ".txt", Method: zip.Deflate, Modified: now}}
	err = s.writeBundle(r.Context(), archive, supportbundle.Full, entry)
	if cerr := archive.Close(); cerr != nil {
		s.o.Logger.Warn("osadmin: a support bundle's zip didn't close: the client has gone", log.F("name", name), log.F("error", cerr.Error()))
	}
	if err != nil && !archive.started() && codes.Is(err, codes.NotAvailable) {
		w.Header().Del("Content-Disposition")
		http.Error(w, codes.Describe(err), http.StatusServiceUnavailable)
	}
}

// firstLabel is a host name's first label, safe in a file name.
func firstLabel(host string) string {
	label, _, _ := strings.Cut(host, ".")
	clean := strings.Map(func(c rune) rune {
		if c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return c
		}
		return -1
	}, label)
	if clean == "" {
		return "box"
	}
	return clean
}
