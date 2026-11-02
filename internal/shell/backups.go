// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

func setLine(b *strings.Builder, s *osadminv1.BoxBackupSet) {
	fmt.Fprintf(b, "%s  %s  %s  %s\n", Printable(s.GetName()), Printable(s.GetTaken()), diskBytes(s.GetBytes()), Printable(s.GetPoint()))
}

func (s *Services) backupSets(ctx context.Context) (Result, error) {
	out, err := s.Access.ListBackups(ctx, connect.NewRequest(&accessv1.ListBackupsRequest{}))
	if err != nil {
		return Result{}, err
	}
	list := out.Msg.GetSets()
	if len(list) == 0 {
		return Result{Text: "No backup sets.\n", Data: map[string]any{"sets": []any{}}}, nil
	}
	var b strings.Builder
	data := make([]map[string]any, 0, len(list))
	for _, x := range list {
		setLine(&b, x)
		data = append(data, map[string]any{"name": x.GetName(), "point": x.GetPoint(), "taken": x.GetTaken(), "bytes": x.GetBytes()})
	}
	return Result{Text: b.String(), Data: map[string]any{"sets": data}}, nil
}

func (s *Services) createBackup(ctx context.Context, args []string) (Result, error) {
	name := ""
	if len(args) == 1 {
		name = args[0]
	}
	out, err := s.Access.CreateBackup(ctx, connect.NewRequest(&accessv1.CreateBackupRequest{Name: name}))
	if err != nil {
		return Result{}, err
	}
	x := out.Msg.GetSet()
	return Result{Text: fmt.Sprintf("The set %s is made, at the restore point %s (%s).\n", Printable(x.GetName()), Printable(x.GetPoint()), diskBytes(x.GetBytes())),
		Data: map[string]any{"name": x.GetName(), "point": x.GetPoint(), "taken": x.GetTaken(), "bytes": x.GetBytes()}}, nil
}

func (s *Services) removeBackup(ctx context.Context, name, code string) (Result, error) {
	if _, err := s.Access.RemoveBackup(ctx, connect.NewRequest(&accessv1.RemoveBackupRequest{TotpCode: code, Name: name})); err != nil {
		return Result{}, err
	}
	return Result{Text: fmt.Sprintf("%s is removed.\n", Printable(name)), Data: map[string]any{"removed": name}}, nil
}

func (s *Services) restoreBackup(ctx context.Context, name, code string) (Result, error) {
	if _, err := s.Access.RestoreBackup(ctx, connect.NewRequest(&accessv1.RestoreBackupRequest{TotpCode: code, Name: name})); err != nil {
		return Result{}, err
	}
	return Result{Text: fmt.Sprintf("The restore of %s has started. The product is offline until it's done: status, or the Product card on Updates, follows it.\n", Printable(name)),
		Data: map[string]any{"restoring": name}}, nil
}

// exportBackup authorises the export, then hands the shell its stream.
func (s *Services) exportBackup(ctx context.Context, name, code string) (Result, error) {
	if s.bundleClient == nil {
		return Result{}, ErrUnavailable
	}
	out, err := s.Access.PrepareBackupExport(ctx, connect.NewRequest(&accessv1.PrepareBackupExportRequest{TotpCode: code, Name: name}))
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.bundleURL+accessapi.BackupExportPath+"?ticket="+url.QueryEscape(out.Msg.GetTicket()), nil)
	if err != nil {
		return Result{}, err
	}
	if s.Session.KeyFingerprint != "" {
		req.Header.Set(accessapi.KeyHeader, s.Session.KeyFingerprint)
	}
	if s.Session.Source != "" {
		req.Header.Set(accessapi.SourceHeader, s.Session.Source)
	}
	resp, err := s.bundleClient.Do(req)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRefusal))
		return Result{}, codes.New(codes.AccessForbidden, "%s", Printable(strings.TrimSpace(string(b))))
	}
	return Result{Stream: closingReader{resp.Body}}, nil
}
