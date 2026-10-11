// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func ruleRow(svc, method string, r *osadminv1.Rule) string {
	who := "public"
	switch r.GetRole() {
	case osadminv1.Role_ROLE_ADMIN:
		who = "admin"
	case osadminv1.Role_ROLE_OWNER:
		who = "owner"
	}
	if r.GetCodeSession() {
		if r.GetRole() == osadminv1.Role_ROLE_UNSPECIFIED {
			who = "code session"
		} else {
			who += " or code session"
		}
	}
	if r.GetSshOnly() {
		who += ", SSH only"
	}
	step := "no"
	switch {
	case r.GetCodeEachCall():
		step = "every call"
	case r.GetStepUp():
		step = "yes"
	}
	audit := ""
	if r.GetAudit() != "" {
		audit = "`" + r.GetAudit() + "`"
	}
	return strings.TrimRight(fmt.Sprintf("| `%s.%s` | %s | %s | %s", svc, method, who, step, audit), " ") + " |"
}

func TestTheAPIReferenceListsEveryMethod(t *testing.T) {
	doc, err := os.ReadFile("../../docs/osadmin-api.md")
	if err != nil {
		t.Fatal(err)
	}
	protoregistry.GlobalFiles.RangeFilesByPackage("sneakers.appliance.osadmin.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			s := fd.Services().Get(i)
			if s.Name() == "LocalService" {
				continue
			}
			for j := range s.Methods().Len() {
				m := s.Methods().Get(j)
				row := ruleRow(string(s.Name()), string(m.Name()), osadmin.RuleOf(m))
				if !strings.Contains(string(doc), row) {
					t.Errorf("docs/osadmin-api.md has no row %s", row)
				}
			}
		}
		return true
	})
}
