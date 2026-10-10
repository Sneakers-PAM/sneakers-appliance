// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-accessd is the root access service: the access store,
// the root key and pepper, the setup and one-time codes, the sessions and
// lockout, the root shells, the OS audit log, the accounts and sshd config
// rendered from the store, and the backend of the :8443 API, served on
// /run/sneakers/access.sock to root, the closed shell's admin uids and
// sneakers-osadmin, each told apart by SO_PEERCRED. Root shells open on
// /run/sneakers/rootshell.sock.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	// The root has no zoneinfo; the box's time zone setting is read from
	// the copy linked in.
	_ "time/tzdata"

	"connectrpc.com/connect"
	"filippo.io/age"
	log "github.com/Bugs5382/go-log"
	// The root image carries no CA bundle, so the update fetches (an
	// https:// mirror with a public certificate, the release source) check
	// against Go's embedded copy of the Mozilla roots.
	_ "golang.org/x/crypto/x509roots/fallback"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kubeapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productedge"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshsession"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukikey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

type config struct {
	state, run, socket, initSock, netdSock, esp, sshd string
}

func main() {
	var c config
	flag.StringVar(&c.state, "state", "/var/lib/sneakers", "the state volume")
	flag.StringVar(&c.run, "run", "/run/sneakers", "where the rendered files and the socket live")
	flag.StringVar(&c.socket, "socket", accessapi.SocketPath, "accessd's socket")
	flag.StringVar(&c.initSock, "init-socket", initapi.SocketPath, "init's socket")
	flag.StringVar(&c.netdSock, "netd-socket", "/run/sneakers/netd.sock", "netd's socket")
	flag.StringVar(&c.esp, "esp", "/run/sneakers/esp", "where init mounts the ESP (the booted UKI carries the update key)")
	flag.StringVar(&c.sshd, "sshd", "/usr/sbin/sshd", "the pinned sshd that checks every rendered config")
	flag.Parse()
	lg := log.NewLoggerWithOptions("sneakers-accessd", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c, lg); err != nil {
		lg.Error(err, "accessd: fatal")
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-accessd:", codes.Describe(err))
		os.Exit(1)
	}
}

// releaseRepo is where a production build fetches from by default: the
// project's GitHub Releases (docs/upgrades.md#the-github-source).
const releaseRepo = "Sneakers-PAM/sneakers-appliance"

func unixClient(sock string) *http.Client { return unixClientWith(sock, 30*time.Second) }

func unixClientWith(sock string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func run(ctx context.Context, c config, lg log.Logger) error {
	ic, nc := unixClient(c.initSock), unixClient(c.netdSock)
	netd := netdv1connect.NewNetworkServiceClient(nc, "http://netd.sock")
	paths := osadmin.Paths{State: c.state}
	if err := dirs(paths); err != nil {
		return err
	}
	// accessd checks every sshd config it renders with sshd -t, which needs
	// sshd's privilege-separation directory.
	if err := sshconfig.EnsurePrivsepDir(sshconfig.PrivsepDir); err != nil {
		return err
	}
	audit, err := osaudit.Open(filepath.Join(c.state, "os-audit"), osaudit.Options{Logger: lg})
	if err != nil {
		return err
	}
	var d *accessd.Server
	var api *osadmin.Server
	rerender := func() {
		if d != nil {
			d.Rerender()
		}
	}
	// The keys the store already revoked go on the first revocation list
	// the elevation service writes; from then on the store's every write
	// rewrites it (access.Options.Revoke).
	stored, err := access.ReadState(filepath.Join(c.state, "access"))
	if err != nil {
		return err
	}
	revokedKeys, err := stored.RevokedPublicKeys()
	if err != nil {
		return err
	}
	custody := initv1connect.NewKeyCustodyServiceClient(ic, "http://init.sock")
	// The root key and the pepper are made at first boot and sealed through
	// init's KeyCustody (docs/access.md).
	root, err := rootkey.Load(accessd.CustodySealer{Client: custody}, paths.SSHDir(), lg)
	if err != nil {
		return err
	}
	if err := accessd.EnsureHostKeys(paths.SSHDir()); err != nil {
		return err
	}
	book, err := lockout.Open(filepath.Join(c.state, "access", "lockout.json"))
	if err != nil {
		return err
	}
	svcs := initv1connect.NewServicesServiceClient(ic, "http://init.sock")
	startSSHD := func() {
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := svcs.Start(sctx, connect.NewRequest(&initv1.StartRequest{Name: "sshd"})); err != nil {
			lg.Warn("accessd: init didn't start sshd", log.F("error", err.Error()))
			return
		}
		lg.Info("accessd: sshd started; an admin can sign in")
	}
	elev, err := elevation.Open(elevation.Options{
		RootKey:        root,
		RevokedKeys:    revokedKeys,
		RevokedSerials: stored.RevokedSerials(),
		SSHDir:         paths.SSHDir(),
		StateFile:      filepath.Join(c.state, "access", "elevation.json"),
		Audit:          audit,
		Logger:         lg,
		OnChange:       rerender,
		// An update being applied or reverted refuses new elevated shells.
		Maintenance: func() bool { return api != nil && api.Maintenance() },
		Signal: func(pid int) error {
			return accessd.SignalElevated(pid, func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) })
		},
		Alive: func(pid int) bool { return syscall.Kill(pid, 0) == nil },
	})
	if err != nil {
		return err
	}
	d = accessd.New(accessd.Options{
		Network:    netd,
		Paths:      accessd.Paths{Run: c.run, SSHD: c.sshd},
		StatusFile: filepath.Join(c.run, "access", "status.json"),
		Elevation:  elev,
		HostKeyDir: paths.SSHDir(),
		HostCA:     root,
		AuditDir:   audit.Dir(),
		Logger:     lg,
	})
	setupDone := func() bool { return api != nil && api.SetupDone() }
	store, err := access.Open(filepath.Join(c.state, "access"), access.Options{
		Stage:    accessd.SetupStage(func() bool { return api != nil && api.FirstAdminDone() }, setupDone),
		Logger:   lg,
		OnChange: d.Changed,
		Revoke:   elev.RevokeLoginKeys,
	})
	if err != nil {
		return err
	}
	go audit.RunRetention(ctx, 24*time.Hour)
	pins, perr := release.Load()
	if perr != nil {
		lg.Error(perr, "accessd: this build carries no release pins; updates can't be verified, so none will stage")
	}
	// The certificate store: keys sealed through KeyCustody, :8443's files
	// handed to the osadmin user (docs/certificates.md).
	certs, err := certstore.Open(certstore.Options{
		Dir: filepath.Join(paths.APIDir(), "tls"), AdminDir: paths.OwnDir(),
		Sealer: accessd.CustodySealer{Client: custody},
		Names: func(ctx context.Context) (string, []string, error) {
			st, err := netd.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
			if err != nil {
				return "", nil, err
			}
			return st.Msg.GetHostname(), accessd.Bindable(st.Msg.GetManagementAddresses()), nil
		},
		OwnName: func() string { name, _ := boxname.Ensure(c.state); return name },
		// The Product (443) endpoint: the box-tls Secret k0s applies, which
		// the edge reloads live.
		Product: &productedge.Edge{Slot: elevated.DefaultProduct, Dir: filepath.Join(c.state, "platform", "tls"), AdminDir: paths.OwnDir(), Manifests: "/var/lib/k0s/manifests"},
		Own:     func(f *os.File) error { return f.Chown(accounts.OsadminUID, accounts.OsadminUID) },
		Logger:  lg,
	})
	if err != nil {
		return err
	}
	settings := &boxsettings.Store{Dir: filepath.Join(c.state, "platform")}
	// The disk guard: the volumes' alerts and the cleanup that runs every
	// hour and when a volume passes 80% (docs/disk-layout.md).
	guard := diskGuard(c.state, paths, audit, func() bool { return api != nil && api.UpdateBusy() }, lg)
	api = osadmin.New(osadmin.Options{
		Access: store, Audit: audit, Clock: clock.Real{}, Disk: guard,
		RootSource: os.Getenv(switchroot.SourceEnv),
		BootID:     bootID(lg),
		KeyCustody: custody,
		Image:      initv1connect.NewImageServiceClient(ic, "http://init.sock"),
		Power:      initv1connect.NewPowerServiceClient(ic, "http://init.sock"),
		// Stopping k0s may take its whole stop-timeout (2 minutes).
		Services: initv1connect.NewServicesServiceClient(unixClientWith(c.initSock, 5*time.Minute), "http://init.sock"),
		Network:  netd,
		// accessd is root, so it may ask the installed bundle's k0s how
		// far the product has come up after an apply (docs/upgrades.md).
		ProductUp: &productup.Probe{
			Slot: filepath.Join(product.Dir, "current"), DataDir: "/var/lib/k0s",
			Containerd: "/run/k0s/containerd.sock", Edge: "127.0.0.1:443",
			SwitchDir: filepath.Join(c.state, "platform"),
		},
		// The installed product's switches (the MCP page): their stacks
		// go in front of k0s or away, and the installed bundle's k0s
		// restarts what reads them.
		Switches: &productswitch.Switches{
			Dir: filepath.Join(c.state, "platform"), Slot: filepath.Join(product.Dir, "current"), Manifests: "/var/lib/k0s/manifests",
			Restart: rolloutRestart(filepath.Join(product.Dir, "current", "k0s"), elevated.DefaultKubeconfig),
			Settled: stackSettled(filepath.Join(product.Dir, "current", "k0s"), elevated.DefaultKubeconfig), Logger: lg,
		},
		// The Secrets the installed product declares, made on this box
		// once and kept on the state volume (docs/release.md#productyaml).
		// They carry the product's email settings too (the Email page),
		// kept 0600 next to them (docs/product-email.md).
		BoxSecrets: &boxsecrets.Store{Dir: filepath.Join(c.state, "platform"), Manifests: "/var/lib/k0s/manifests", Settings: settings, Logger: lg},
		Email:      settings,
		EmailWorkloads: emailWorkloads{
			k0s: filepath.Join(product.Dir, "current", "k0s"), kubeconfig: elevated.DefaultKubeconfig,
			stack: filepath.Join("/var/lib/k0s/manifests", productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"),
		},
		Paths:           paths,
		BoxStateFile:    boxstate.File,
		CertDir:         paths.OwnDir(),
		Certs:           certs,
		Elevation:       elev,
		RootKey:         root,
		CodeSealer:      accessd.CustodySealer{Client: custody},
		Lockout:         book,
		OnFirstAdmin:    func() { go startSSHD() },
		OnConsoleChange: d.ConsoleChanged,
		Shells:          &sshsession.Proc{},
		// The installed product's exposed values, read as the appliance's
		// own service account (the admin kubeconfig only mints its token).
		Exposed: &kubeapi.Client{Kubeconfig: elevated.DefaultKubeconfig, Namespace: productspec.Namespace, ServiceAccount: productspec.ServiceAccount},
		// The box's FQDN the product's stacks take in place of the bundle's
		// placeholder (docs/network.md#the-host-name).
		BoxValues: &boxvalues.Box{
			Dir: filepath.Join(c.state, "platform"),
			Names: func(ctx context.Context) (string, []string, error) {
				st, err := netd.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
				if err != nil {
					return "", nil, err
				}
				return st.Msg.GetHostname(), accessd.Bindable(st.Msg.GetManagementAddresses()), nil
			},
			Own: func() string { name, _ := boxname.Ensure(c.state); return name },
			// The Base OS and Base Web versions for the product's About.
			Versions: func() (string, string) {
				return release.Version, webslots.ServedVersion(filepath.Join(paths.OwnDir(), osadmin.WebServedFile), release.Version)
			},
		},
		Logger: lg,
		Upgrade: osadmin.UpgradeOptions{
			Channel: pins.Channel, ReleaseKeyPEM: pins.ReleaseKeyPEM,
			// The update key is read from the running UKI on each use and
			// never written to disk; sneakers-upgraded takes this over
			// when it lands (the upgrades design).
			UpdateKey: func() (age.Identity, error) {
				return ukikey.Running(secureboot.Efivarfs{Dir: secureboot.DefaultEfivarfs}, os.DirFS(c.esp))
			},
			ReleaseRepo: releaseRepoFor(pins.Channel),
			Arch:        runtime.GOARCH,
			// sneakers-osadmin serves the pages and says which it serves.
			WebServedFile:  filepath.Join(paths.OwnDir(), osadmin.WebServedFile),
			BuiltinMirrors: builtinMirrors(),
		},
	})
	d.Attach(store, api)
	// The host certificates name the box's host name and addresses: a
	// change re-renders sshd's files, which signs them again.
	// The product follows a changed host name too, once the change is
	// kept (osadmin.HostNameChanged); it looks once at start as well.
	go api.HostNameChanged(ctx)
	go watchNames(ctx, netdapi.NewClient(c.netdSock), lg, func() {
		d.Rerender()
		go api.HostNameChanged(ctx)
	})
	defer api.Close()

	srv, err := listen(c.socket, d, lg)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	rs, err := listenRootShell(filepath.Join(c.run, "rootshell.sock"), lg)
	if err != nil {
		return err
	}
	go d.ServeRootShells(ctx, rs)
	if osadmin.HasSignInAdmin(store.Read()) {
		// A box past its first admin: sshd runs (in first boot it starts
		// on demand only).
		go startSSHD()
	}
	ready := filepath.Join(c.run, filepath.Base(accessapi.ReadyFile))
	if err := os.WriteFile(ready, nil, 0o644); err != nil { // #nosec G306 -- an empty readiness marker
		return err
	}
	defer func() { _ = os.Remove(ready) }()
	lg.Info("accessd: ready", log.F("socket", c.socket))

	go runDiskGuard(ctx, guard)
	d.RefreshStatus(ctx)
	api.ResumeProductUp()
	// netd keeps the product's ports only while it runs: open them again
	// at start, and each minute until that works.
	portsOpen := api.OpenProductPorts(ctx) == nil
	// The release the box booted is committed once the box is healthy on
	// it; until then boot counting would fall back from it.
	good := api.MarkGood(ctx) == nil
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	for {
		select {
		case <-ctx.Done():
			lg.Info("accessd: stopped")
			return nil
		case <-minute.C:
			d.Tick()
			api.UpgradeWindowTick(ctx)
			api.RebootWatchdog()
			if !portsOpen {
				portsOpen = api.OpenProductPorts(ctx) == nil
			}
			if !good {
				good = api.MarkGood(ctx) == nil
			}
			d.RefreshStatus(ctx)
		}
	}
}

// rolloutRestart restarts a workload with the installed bundle's k0s as
// kubectl on the admin kubeconfig.
func rolloutRestart(k0s, kubeconfig string) func(ctx context.Context, ns, kind, name string) error {
	return func(ctx context.Context, ns, kind, name string) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, k0s, "kubectl", "--kubeconfig", kubeconfig, "-n", ns, "rollout", "restart", kind+"/"+name).CombinedOutput() // #nosec G204 -- the installed bundle's k0s on a workload product.yaml names
		if err != nil {
			return fmt.Errorf("rollout restart %s/%s/%s: %w: %s", ns, kind, name, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// emailWorkloads restart what reads the product's email settings once k0s
// has applied the box secrets stack as it is on disk: every object in the
// cluster carries the stack's revision.
type emailWorkloads struct{ k0s, kubeconfig, stack string }

func (w emailWorkloads) Applied(ctx context.Context) error {
	want, err := boxsecrets.StackRevision(w.stack)
	if err != nil {
		return err
	}
	jp := `{range .items[*]}{.metadata.annotations['` + boxsecrets.RevisionAnnotation + `']}{"\n"}{end}`
	for {
		out, err := exec.CommandContext(ctx, w.k0s, "kubectl", "--kubeconfig", w.kubeconfig, "get", "-f", w.stack, "-o", "jsonpath="+jp).CombinedOutput() // #nosec G204 -- the installed bundle's k0s on the box's own stack
		if err == nil && allEqual(strings.Fields(string(out)), want) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the box secrets stack isn't applied at revision %s: %s", want, strings.TrimSpace(string(out)))
		case <-time.After(3 * time.Second):
		}
	}
}

func (w emailWorkloads) Restart(ctx context.Context, ns, kind, name string) error {
	return rolloutRestart(w.k0s, w.kubeconfig)(ctx, ns, kind, name)
}

func allEqual(got []string, want string) bool {
	if len(got) == 0 {
		return false
	}
	for _, g := range got {
		if g != want {
			return false
		}
	}
	return true
}

// stackSettled waits, up to 90 s, until every object in a stack's files is
// in the cluster (on) or none is left (off): k0s applies a stack it finds in
// its manifests directory a moment later, and a workload restarted before
// then misses the objects it loads.
func stackSettled(k0s, kubeconfig string) func(ctx context.Context, stack string, on bool) error {
	return func(ctx context.Context, stack string, on bool) error {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		for {
			args := []string{"kubectl", "--kubeconfig", kubeconfig, "get", "-f", stack, "-o", "name"}
			if !on {
				args = append(args, "--ignore-not-found")
			}
			out, err := exec.CommandContext(ctx, k0s, args...).CombinedOutput() // #nosec G204 -- the installed bundle's k0s on the installed slot's own stack
			if (on && err == nil) || (!on && err == nil && strings.TrimSpace(string(out)) == "") {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("stack %s not settled (on %v): %s", filepath.Base(stack), on, strings.TrimSpace(string(out)))
			case <-time.After(time.Second):
			}
		}
	}
}

// watchNames calls changed on each of netd's address and host name events
// after the first; a broken stream is opened again.
func watchNames(ctx context.Context, netd netdv1connect.NetworkServiceClient, lg log.Logger, changed func()) {
	for ctx.Err() == nil {
		stream, err := netd.Watch(ctx, connect.NewRequest(&netdv1.WatchRequest{}))
		if err == nil {
			first := true
			for stream.Receive() {
				if !first {
					lg.Info("accessd: the box's addresses or host name changed; re-signing the host certificates", log.F("hostname", stream.Msg().GetHostname()))
					changed()
				}
				first = false
			}
			err = stream.Err()
			_ = stream.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("the stream ended")
		}
		lg.Warn("accessd: netd's address events stopped; watching again", log.F("error", err.Error()))
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		changed()
	}
}

// bootID is the kernel's boot ID, or empty (no reboot watchdog) when it
// doesn't read.
func bootID(lg log.Logger) string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		lg.Warn("accessd: the boot ID doesn't read; the reboot watchdog is off", log.F("error", err.Error()))
		return ""
	}
	return strings.TrimSpace(string(b))
}

// builtinMirrors is the built-in source list a lab build names.
func builtinMirrors() []string {
	var out []string
	for _, u := range strings.Split(release.Mirrors, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// releaseRepoFor is the GitHub repository a build fetches from; a lab
// build has none (lab packages are never published there), unless its
// update policy names a test repository.
func releaseRepoFor(channel string) string {
	if channel == release.ChannelProduction {
		return releaseRepo
	}
	return ""
}

// dirs makes osadmin's own directory (its certificate, written as the
// osadmin user; a certificate an earlier root osadmin left there is handed
// over) and the API's root-only one.
// stateDirMode lets every uid pass through the state directory, but not
// list it.
const stateDirMode = 0o711

func dirs(p osadmin.Paths) error {
	// The state directory is searchable by the services that run
	// unprivileged (osadmin keeps its certificate in its own directory under
	// it); MkdirAll of a subdirectory would otherwise make it 0700.
	if err := os.MkdirAll(p.State, stateDirMode); err != nil {
		return err
	}
	if err := os.Chmod(p.State, stateDirMode); err != nil { // #nosec G302 -- search only: every entry under it has its own mode
		return err
	}
	if err := os.MkdirAll(p.APIDir(), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.OwnDir(), 0o700); err != nil {
		return err
	}
	if err := os.Chown(p.OwnDir(), accounts.OsadminUID, accounts.OsadminUID); err != nil {
		return err
	}
	for _, name := range []string{"tls.crt", "tls.key", certstore.AssignedMarker} {
		err := os.Lchown(filepath.Join(p.OwnDir(), name), accounts.OsadminUID, accounts.OsadminUID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// listenRootShell opens rootshell.sock: mode 0666, since admin uids
// connect; SO_PEERCRED lets only admin uids through.
func listenRootShell(path string, lg log.Logger) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- the peer uid is checked on every connection
		_ = ln.Close()
		return nil, err
	}
	logf := func(format string, args ...any) { lg.Warn(fmt.Sprintf(format, args...)) }
	return initapi.PeerListener(ln, accessd.AdminPeer, logf), nil
}

// listen serves access.sock: mode 0666, since admin uids and osadmin
// connect, and SO_PEERCRED decides who is let through.
func listen(path string, d *accessd.Server, lg log.Logger) (*http.Server, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- the peer uid is checked on every connection
		_ = ln.Close()
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	hs := &http.Server{Handler: d.Handler(), Protocols: protocols, ConnContext: initapi.PeerContext, ReadHeaderTimeout: 10 * time.Second}
	logf := func(format string, args ...any) { lg.Warn(fmt.Sprintf(format, args...)) }
	go func() {
		if err := hs.Serve(initapi.PeerListener(ln, accessd.PeerAllowed, logf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Error(err, "accessd: socket stopped")
		}
	}()
	return hs, nil
}
