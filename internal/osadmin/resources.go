// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"slices"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/resources"
)

// ResourcesBackend is the installed product's PostgreSQL cluster as the
// Resources page sees it.
type ResourcesBackend interface {
	// State is what the cluster is doing now.
	State(ctx context.Context, c resources.Cluster) (resources.State, error)
	// Settings are the settings in force, given what the cluster is doing
	// now. poolsKnown is false when PgBouncer's sizes can't be said.
	Settings(ctx context.Context, st resources.State) (s resources.Settings, poolsKnown bool, err error)
	// Nodes is how many nodes the cluster has.
	Nodes(ctx context.Context) (int, error)
}

type resourcesSvc struct {
	osadminv1connect.UnimplementedResourcesServiceHandler
	s *Server
}

// cluster is the installed product's PostgreSQL cluster: the one its data
// move targets.
func (h *resourcesSvc) cluster() (resources.Cluster, error) {
	info, spec := h.s.installedSpec()
	switch {
	case !info.Present():
		return resources.Cluster{}, codes.New(codes.NotAvailable, "no product is installed")
	case spec.DataMove == nil:
		return resources.Cluster{}, codes.New(codes.NotAvailable, "%s has no PostgreSQL cluster to manage", info.Title)
	case h.s.o.Resources == nil:
		return resources.Cluster{}, codes.New(codes.NotAvailable, "this box can't read the product's PostgreSQL cluster")
	}
	return spec.DataMove.Target, nil
}

func settingsToWire(s resources.Settings) *osadminv1.ResourceSettings {
	p := s.Pools
	return &osadminv1.ResourceSettings{
		Replicas: int32(s.Replicas), StorageBytes: s.StorageBytes, Parameters: s.Parameters, // #nosec G115 -- a replica count fits an int32
		Pools: &osadminv1.PgBouncerPools{DefaultPoolSize: int32(p.DefaultPoolSize), MinPoolSize: int32(p.MinPoolSize), ReservePoolSize: int32(p.ReservePoolSize), // #nosec G115 -- pool sizes fit an int32
			MaxClientConn: int32(p.MaxClientConn), MaxDbConnections: int32(p.MaxDBConns)}, // #nosec G115 -- as above
	}
}

func settingsFromWire(w *osadminv1.ResourceSettings) resources.Settings {
	p := w.GetPools()
	return resources.Settings{
		Replicas: int(w.GetReplicas()), StorageBytes: w.GetStorageBytes(), Parameters: w.GetParameters(),
		Pools: resources.Pools{DefaultPoolSize: int(p.GetDefaultPoolSize()), MinPoolSize: int(p.GetMinPoolSize()), ReservePoolSize: int(p.GetReservePoolSize()),
			MaxClientConn: int(p.GetMaxClientConn()), MaxDBConns: int(p.GetMaxDbConnections())},
	}
}

// clusterUnreadable words a cluster that can't be read, so the page says so instead
// of showing it empty.
func clusterUnreadable(err error) error {
	return codes.New(codes.ResourcesUnavailable, "the PostgreSQL cluster can't be read: %v", err)
}

func (h *resourcesSvc) GetResources(ctx context.Context, _ *connect.Request[osadminv1.GetResourcesRequest]) (*connect.Response[osadminv1.GetResourcesResponse], error) {
	c, err := h.cluster()
	if err != nil {
		return nil, err
	}
	b := h.s.o.Resources
	st, err := b.State(ctx, c)
	if err != nil {
		h.s.o.Logger.Warn("osadmin: resources: the cluster can't be read", log.F("cluster", c.Name), log.F("error", err.Error()))
		return nil, clusterUnreadable(err)
	}
	set, poolsKnown, err := b.Settings(ctx, st)
	if err != nil {
		return nil, clusterUnreadable(err)
	}
	nodes, err := b.Nodes(ctx)
	if err != nil {
		return nil, clusterUnreadable(err)
	}
	out := &osadminv1.GetResourcesResponse{
		Settings: settingsToWire(set), PoolsKnown: poolsKnown, Nodes: int32(nodes), // #nosec G115 -- a node count fits an int32
		Storage: &osadminv1.ResourceStorage{SizeBytes: st.Storage.SizeBytes, UsedBytes: st.Storage.UsedBytes},
	}
	for _, r := range st.Replicas {
		out.Replicas = append(out.Replicas, &osadminv1.ResourceReplica{Name: r.Name, Role: r.Role, State: r.State, Healthy: r.Healthy, LagBytes: r.LagBytes})
	}
	for _, p := range st.Parameters {
		out.Parameters = append(out.Parameters, &osadminv1.ResourceParameter{Name: p.Name, Value: p.Value, Unit: p.Unit, DefaultValue: p.Default,
			NeedsRestart: p.NeedsRestart, PendingRestart: p.PendingRestart, Known: p.Known})
	}
	return connect.NewResponse(out), nil
}

func (h *resourcesSvc) PreviewResources(ctx context.Context, r *connect.Request[osadminv1.PreviewResourcesRequest]) (*connect.Response[osadminv1.PreviewResourcesResponse], error) {
	c, err := h.cluster()
	if err != nil {
		return nil, err
	}
	b := h.s.o.Resources
	st, err := b.State(ctx, c)
	if err != nil {
		return nil, clusterUnreadable(err)
	}
	cur, _, err := b.Settings(ctx, st)
	if err != nil {
		return nil, clusterUnreadable(err)
	}
	nodes, err := b.Nodes(ctx)
	if err != nil {
		return nil, clusterUnreadable(err)
	}
	staged := settingsFromWire(r.Msg.GetStaged())
	plan, err := resources.Preview(cur, staged, nodes)
	if err != nil {
		return nil, err
	}
	out := &osadminv1.PreviewResourcesResponse{Warnings: plan.Warnings}
	for _, ch := range plan.Changes {
		out.Changes = append(out.Changes, &osadminv1.ResourceChange{Field: ch.Field, Before: ch.Before, After: ch.After, RestartRequired: ch.RestartRequired})
	}
	out.RestartRequired = slices.ContainsFunc(plan.Changes, func(ch resources.Change) bool { return ch.RestartRequired })
	return connect.NewResponse(out), nil
}
