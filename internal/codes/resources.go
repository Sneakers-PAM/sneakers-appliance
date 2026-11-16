// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The product's Resources page codes: 392x.
const (
	ResourcesInvalid     = 3920
	ResourcesUnavailable = 3921
)

var resourcesEntries = []apperr.Entry{
	{Code: ResourcesInvalid, Symbol: "RESOURCES_INVALID", Title: "resources", Cause: "a setting fails validation (the error names it): no replicas, storage that would shrink, a malformed parameter or a pool size out of range"},
	{Code: ResourcesUnavailable, Symbol: "RESOURCES_UNAVAILABLE", Title: "resources", Cause: "there's no product installed, or the installed product has no PostgreSQL cluster to manage, or the cluster can't be read"},
}

func init() { Entries = append(Entries, resourcesEntries...) }
