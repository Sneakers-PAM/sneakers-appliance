// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"log/slog"

	log "github.com/Bugs5382/go-log"
)

// SlogHandler hands log/slog records (the SNTP engine, ported with its
// slog calls) to lg, so netd has one log.
func SlogHandler(lg log.Logger) slog.Handler { return slogHandler{lg: lg} }

type slogHandler struct {
	lg    log.Logger
	attrs []log.Field
}

func (slogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h slogHandler) Handle(_ context.Context, r slog.Record) error {
	fields := append([]log.Field(nil), h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		fields = append(fields, log.F(a.Key, a.Value.Any()))
		return true
	})
	switch {
	case r.Level >= slog.LevelError:
		h.lg.Error(nil, r.Message, fields...)
	case r.Level >= slog.LevelWarn:
		h.lg.Warn(r.Message, fields...)
	case r.Level >= slog.LevelInfo:
		h.lg.Info(r.Message, fields...)
	case r.Level >= slog.LevelDebug:
		h.lg.Debug(r.Message, fields...)
	default:
		log.Trace(h.lg, r.Message, fields...)
	}
	return nil
}

func (h slogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := slogHandler{lg: h.lg, attrs: append([]log.Field(nil), h.attrs...)}
	for _, a := range as {
		n.attrs = append(n.attrs, log.F(a.Key, a.Value.Any()))
	}
	return n
}

func (h slogHandler) WithGroup(string) slog.Handler { return h }
