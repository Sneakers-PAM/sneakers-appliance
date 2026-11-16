// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type kind int

const (
	kInt kind = iota
	kReal
	kBool
	kSize
	kTime
	kEnum
	kString
)

var (
	sizeRE = regexp.MustCompile(`^\d+(kB|MB|GB|TB)?$`)
	timeRE = regexp.MustCompile(`^\d+(us|ms|s|min|h|d)?$`)
	intRE  = regexp.MustCompile(`^-?\d+$`)
	realRE = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
)

func (k kind) valid(v string, enum []string) bool {
	switch k {
	case kInt:
		return intRE.MatchString(v)
	case kReal:
		return realRE.MatchString(v)
	case kBool:
		return slices.Contains([]string{"on", "off", "true", "false", "yes", "no", "1", "0"}, strings.ToLower(v))
	case kSize:
		return sizeRE.MatchString(v)
	case kTime:
		return timeRE.MatchString(v)
	case kEnum:
		return slices.Contains(enum, v)
	}
	return true
}

func (k kind) describe(enum []string) string {
	switch k {
	case kInt:
		return "a whole number"
	case kReal:
		return "a number"
	case kBool:
		return "on or off"
	case kSize:
		return "a size such as 512MB or 1GB"
	case kTime:
		return "a time such as 30s or 5min"
	case kEnum:
		return "one of " + strings.Join(enum, ", ")
	}
	return "a value"
}

type param struct {
	kind    kind
	enum    []string
	restart bool
}

// catalog is the parameters the box knows how to check, and which of them
// PostgreSQL reads only at start. The live Resources page lists every
// parameter the server has (State); this is only for checking an edit.
var catalog = map[string]param{
	"shared_buffers":                      {kind: kSize, restart: true},
	"work_mem":                            {kind: kSize},
	"maintenance_work_mem":                {kind: kSize},
	"effective_cache_size":                {kind: kSize},
	"wal_buffers":                         {kind: kSize, restart: true},
	"max_wal_size":                        {kind: kSize},
	"min_wal_size":                        {kind: kSize},
	"temp_file_limit":                     {kind: kSize},
	"max_connections":                     {kind: kInt, restart: true},
	"max_worker_processes":                {kind: kInt, restart: true},
	"max_parallel_workers":                {kind: kInt},
	"max_parallel_workers_per_gather":     {kind: kInt},
	"max_wal_senders":                     {kind: kInt, restart: true},
	"default_statistics_target":           {kind: kInt},
	"autovacuum_max_workers":              {kind: kInt, restart: true},
	"checkpoint_timeout":                  {kind: kTime},
	"statement_timeout":                   {kind: kTime},
	"lock_timeout":                        {kind: kTime},
	"idle_in_transaction_session_timeout": {kind: kTime},
	"log_min_duration_statement":          {kind: kTime},
	"random_page_cost":                    {kind: kReal},
	"seq_page_cost":                       {kind: kReal},
	"checkpoint_completion_target":        {kind: kReal},
	"autovacuum":                          {kind: kBool},
	"jit":                                 {kind: kBool},
	"fsync":                               {kind: kBool},
	"synchronous_commit":                  {kind: kEnum, enum: []string{"on", "off", "local", "remote_write", "remote_apply"}},
	"log_statement":                       {kind: kEnum, enum: []string{"none", "ddl", "mod", "all"}},
	"log_min_messages":                    {kind: kEnum, enum: []string{"debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error", "log", "fatal", "panic"}},
	"application_name":                    {kind: kString},
}

// ParseSize reads a storage size: a whole number with an optional Ki, Mi, Gi
// or Ti suffix (bytes without one).
func ParseSize(s string) (int64, error) {
	units := map[string]int64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40}
	mult, num := int64(1), s
	if len(s) > 2 {
		if m, ok := units[s[len(s)-2:]]; ok {
			mult, num = m, s[:len(s)-2]
		}
	}
	if !regexp.MustCompile(`^\d+$`).MatchString(num) {
		return 0, fmt.Errorf("%q isn't a size: a whole number with Ki, Mi, Gi or Ti", s)
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("%q isn't a size this box can hold", s)
	}
	return n * mult, nil
}

// FormatSize is the largest whole Ti, Gi, Mi or Ki that holds n exactly,
// else bytes.
func FormatSize(n int64) string {
	for _, u := range []struct {
		suffix string
		size   int64
	}{{"Ti", 1 << 40}, {"Gi", 1 << 30}, {"Mi", 1 << 20}, {"Ki", 1 << 10}} {
		if n >= u.size && n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}
