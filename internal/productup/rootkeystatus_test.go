// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootrotate"
)

// vaultPod serves what the vault's health check answers: the status in the
// sneakers-root-key header.
func vaultPod(t *testing.T, header string) (ip, port string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/grpc.health.v1.Health/Check" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "not the health check", http.StatusNotFound)
			return
		}
		w.Header().Set("Sneakers-Root-Key", header)
		_, _ = w.Write([]byte(`{"status":"SERVING"}`))
	}))
	t.Cleanup(srv.Close)
	ip, port, _ = net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	return ip, port
}

func kubectlFor(workload, pods string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get deployment sneakers-vault"):
			return []byte(workload), nil
		case strings.Contains(joined, "get pods") && strings.Contains(joined, "app=vault"):
			return []byte(pods), nil
		}
		return nil, fmt.Errorf("unexpected: %s", joined)
	}
}

const vaultDeployment = `{"spec":{"selector":{"matchLabels":{"app":"vault"}},"template":{"spec":{"containers":[{"name":"vault","ports":[{"name":"grpc","containerPort":9102}],"env":[{"name":"HEALTH_PORT","value":"%s"}]}]}}}}`

func podList(ip, start string) string {
	return fmt.Sprintf(`{"items":[{"metadata":{"name":"sneakers-vault-0"},"status":{"podIP":%q,"startTime":%q}}]}`, ip, start)
}

// The status is read from the health port of a vault pod that started at or
// after the restart; a pod from before it is not asked.
func TestTheVaultsStatusIsReadFromANewPod(t *testing.T) {
	ip, port := vaultPod(t, `{"state":"verified","pending":0}`)
	now := time.Now().UTC().Truncate(time.Second)
	p := &productup.Probe{Run: kubectlFor(fmt.Sprintf(vaultDeployment, port), podList(ip, now.Add(time.Minute).Format(time.RFC3339)))}
	st, err := p.RootKeyStatus(context.Background(), "sneakers", "Deployment", "sneakers-vault", now)
	if err != nil || st.State != rootrotate.StateVerified || st.Pending != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	old := &productup.Probe{Run: kubectlFor(fmt.Sprintf(vaultDeployment, port), podList(ip, now.Add(-time.Minute).Format(time.RFC3339)))}
	if _, err := old.RootKeyStatus(context.Background(), "sneakers", "Deployment", "sneakers-vault", now); err == nil {
		t.Fatal("a pod from before the restart answered")
	}
}

func TestAFailedStatusCarriesTheCount(t *testing.T) {
	ip, port := vaultPod(t, `{"state":"failed","pending":3}`)
	now := time.Now().UTC().Truncate(time.Second)
	p := &productup.Probe{Run: kubectlFor(fmt.Sprintf(vaultDeployment, port), podList(ip, now.Format(time.RFC3339)))}
	st, err := p.RootKeyStatus(context.Background(), "sneakers", "Deployment", "sneakers-vault", now)
	if err != nil || st.State != rootrotate.StateFailed || st.Pending != 3 {
		t.Fatalf("%+v %v", st, err)
	}
}

// A pod with no status header, or one that isn't up, is not an answer.
func TestAPodWithoutAStatusIsNoAnswer(t *testing.T) {
	ip, port := vaultPod(t, "")
	now := time.Now().UTC().Truncate(time.Second)
	p := &productup.Probe{Run: kubectlFor(fmt.Sprintf(vaultDeployment, port), podList(ip, now.Format(time.RFC3339)))}
	if _, err := p.RootKeyStatus(context.Background(), "sneakers", "Deployment", "sneakers-vault", now); err == nil {
		t.Fatal("no header was taken as an answer")
	}
	none := &productup.Probe{Run: kubectlFor(fmt.Sprintf(vaultDeployment, port), `{"items":[]}`)}
	if _, err := none.RootKeyStatus(context.Background(), "sneakers", "Deployment", "sneakers-vault", now); err == nil {
		t.Fatal("no pod was taken as an answer")
	}
}
