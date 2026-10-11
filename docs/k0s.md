# k0s on the box

The appliance runs one k0s node: the controller with its worker (`k0s controller --enable-worker
--no-taints`), a one-member etcd, kube-router for the pod network and kube-proxy in iptables mode.
It isn't in the base image: k0s, its images and the product's stacks ship as the product bundle,
installed after setup from the Updates page into its own slot on the state volume
([upgrades.md](upgrades.md#the-product-bundle)). It starts in normal operation only, once the first
admin exists and a bundle is installed, from that bundle's images, with no registry to reach.

**Interim.** Until `sneakers-platformd` lands (#99, spec 3), the service table starts k0s through
a small script, `os/k0s/k0s-interim`, which stands in for platformd: it prepares the box and
starts k0s. The lab product bundle also carries a throwaway hello-world stack and a minimal edge
on 443. platformd replaces the script,
renders the config and deploys the real platform; the hello stack goes then.

## What runs

| Piece | Where | What |
|---|---|---|
| Service entry | `os/rootfs/services.d/k0s.yaml` | waits (`start-when`, [init.md](init.md#the-service-table)) for `/var/lib/sneakers/setup/done` and the installed bundle, `/var/lib/sneakers/product/current/bundle.json`, so a box with no bundle runs no k0s; a product apply or revert restarts it through the Services API. `k0s-interim run` (`exec`s `<current slot>/k0s controller --enable-worker --no-taints --config /run/sneakers/k0s/k0s.yaml --data-dir /var/lib/k0s --profile sneakers`), root, `restart: always`, `stop-timeout: 2m`, with `pre-stop: sneakers-accessd quiesce` (the product stops latest phase first, [upgrades.md](upgrades.md#the-phases)), after netd, phase `normal` only (the data directory is on the state volume). konnectivity, metrics-server, autopilot and the update prober are disabled: none is bundled, and the prober would reach the internet. While the console service owns the consoles, k0s's output goes to `/run/sneakers/console.log`. |
| Pre-start (interim) | `k0s-interim prepare` (`/usr/libexec/sneakers/k0s-interim`) | refuses to go on without an installed bundle; mounts cgroup2 on `/sys/fs/cgroup` when it isn't; reads the box's node name (below) and stops when there's none; makes `/var/lib/sneakers/machine-id` once; puts `198.18.0.1/32` on the `sneakers0` dummy interface and routes the Service range there (below); renders the config into `/run/sneakers/k0s/`; makes the CNI and log directories, and copies the installed CNI plugins into the box's own `/var/lib/sneakers/k0s/cni-bin` (below); writes an empty `/run/sneakers/resolv.conf` if netd hasn't written one, and the kubelet's resolver file from it (below); links the bundle's images into `/var/lib/k0s/images/`; copies each of the bundle's stacks, `<slot>/manifests/<name>/`, to `/var/lib/k0s/manifests/<name>/`; writes the `box-tls` Secret for the interim edge: the certificate assigned to the Product (443) endpoint, else the box's own :8443 one (below) |
| Box secrets | accessd, at each product apply and revert | the Secrets the bundle's `product.yaml` declares as `box_secrets`, made on the box once and kept in `/var/lib/sneakers/platform/box-secrets.json`, written as the stack `sneakers-appliance-secrets` before k0s restarts ([release.md](release.md#productyaml)); `k0s-interim` leaves that stack alone |
| Cluster config | `/etc/k0s/k0s.yaml.tmpl` (`os/k0s/k0s.yaml.tmpl`) | the API, etcd peer and node address `198.18.0.1`; the pod range `10.244.0.0/16` and the Service range `10.96.0.0/12` (k0s's defaults, named, and the defaults of the box's network settings, [network.md](network.md)); every system image pinned by `<tag>@sha256:<digest>`; `default_pull_policy: Never`; NodePorts on every address; telemetry off; etcd storage named `@NODE_NAME@`, the one field rendered; the `sneakers` worker profile, the kubelet's image garbage collection (90% down to 85%), container-log rotation (10 MiB, 3 files) and disk eviction (5% free) set explicitly ([disk-layout.md](disk-layout.md#keeping-the-disk-from-filling)) <!-- scrub:allow=private-ip --> |
| containerd config | `/etc/k0s/containerd.toml` (`os/k0s/containerd.toml`) | what k0s would write, with the sandbox (pause) image pinned by digest and the CNI plugins taken from `/var/lib/sneakers/k0s/cni-bin` first, then `/opt/cni/bin` (below). It isn't marked `k0s_managed`, so k0s uses it as it is instead of writing into the read-only `/etc`. Drop-ins: `/etc/k0s/containerd.d/` (empty). |
| Host paths in the root | the root | `/etc/cni -> /var/lib/cni-conf` and `/opt -> /var/lib/opt` (kube-router installs the CNI config and plugins there), `/var/run -> /run` (containerd's NRI socket), `/var/log -> /var/lib/log` (pod logs), `/etc/machine-id -> /var/lib/sneakers/machine-id`, `/etc/hosts` (localhost), `/bin/mount` and `/bin/umount` (busybox; the kubelet mounts tmpfs volumes with them), `/lib/modules` (empty: the kernel has no loadable modules), `/usr/libexec/k0s/kubelet-plugins/volume/exec` (empty) |

k0s runs etcd, the API server and the scheduler as root here: the box has no `etcd`,
`kube-apiserver` or `kube-scheduler` accounts, and k0s falls back to root when it can't find them.

### The node's address and name

The node's address is `198.18.0.1` on `sneakers0` (spec 3: RFC 2544 space, never routed), so a
DHCP change on a real interface never changes the API server's certificates, etcd's peer address
or the node's address. Its name is the box's own name, `sneakers-<8 hex>`, which init makes once at boot and keeps in
`/var/lib/sneakers/box-name` ([network.md](network.md#dns-ntp-and-the-host-name); a box that
already had a node name in `/var/lib/sneakers/k0s/node-name` keeps it). It's the kubelet's node name
(`--hostname-override`) and the etcd member name, and it doesn't follow the host name netd sets, so
it stays the same across reboots and upgrades and is unique when more boxes join.

The Service range is routed on `sneakers0` too. kube-proxy reaches a ClusterIP by rewriting it
(DNAT) on the way out, but the kernel looks up a route before that rewrite, so a host with no
route covering the ClusterIP fails `connect()` with "network is unreachable". kube-router talks to
the API through the `kubernetes` Service, so on a management network with no gateway
(a static address without one, or QEMU's restricted user network in the image suite) it never
started, and with it the pod network: pods stayed in ContainerCreating on the bridge CNI's "no IP
ranges". With the route the cluster doesn't depend on the management network's gateway, the same
as its address.

### The CNI plugins containerd runs

kube-router's `install-cni-bins` init container (the `cni-node` image) installs the CNI plugins
into `/opt/cni/bin` each time the kube-router pod starts, writing each file in place. After a
reboot the CNI config and the plugins are still on the state volume, so containerd starts every
pod's sandbox at once, while the installer is rewriting the plugins. An exec of a plugin that is
open for writing fails with `ETXTBSY`, and libcni (v1.3, in containerd 2.3) retries that by
running the same `exec.Cmd` again, which fails with `exec: already started`: pods, CoreDNS among
them, failed with `FailedCreatePodSandBox` until the kubelet's next try.

So containerd doesn't run the installer's files. At each start, before k0s, `k0s-interim prepare`
copies every plugin in `/opt/cni/bin` into `/var/lib/sneakers/k0s/cni-bin` (a changed one by
rename, an unchanged one left alone, compared by SHA-256), and `containerd.toml` puts that
directory first in `bin_dirs`. Nothing writes the copy while k0s runs. `/opt/cni/bin` comes after
it for a box's first start, when the copy is empty; then there's no CNI config until the installer
has finished (`install-cniconf` runs after it), so nothing runs a plugin mid-write. A k0s update
that brings new plugins puts them in the copy at the next k0s start.

A phased product's first phase waits for kube-router and CoreDNS to be ready (the `cluster` step,
[upgrades.md](upgrades.md#the-phases)), so a sandbox that failed here holds the product's pods back
rather than starting them with no cluster DNS.

### Cluster DNS with no DNS server

The box runs with no DNS server ([network.md](network.md#dns-ntp-and-the-host-name): the `dns`
check only warns), and so must k0s. CoreDNS runs with `dnsPolicy: Default` and forwards every name
outside the cluster to the servers in the kubelet's resolver file, and with no server there it
exits at start (`plugin/forward: no valid upstream addresses found`). So the kubelet has its own
file, `/run/sneakers/k0s/resolv.conf` (`--resolv-conf`), which `k0s-interim prepare` writes at
each start: a copy of netd's `/run/sneakers/resolv.conf` when that names a server, otherwise its
search list and `nameserver 198.18.0.1`, the node address, where nothing serves DNS. Cluster names
resolve, and names outside the cluster fail (`SERVFAIL`) instead of CoreDNS crash-looping.

The image suite hits this: its QEMU user network is `restrict=on`, and then QEMU's DHCP server
offers no router and no DNS server.

The kubelet hands a pod its resolver at the pod's start, so CoreDNS takes a server netd learns
later at k0s's next start (a reboot, a product apply or revert).

### Multi-node later (spec 3, Section 2.12)

k0s runs as `controller --enable-worker --no-taints` with a one-member etcd, never `--single` with
kine, which can't take more nodes. Nothing here assumes one node: the hello stack is a Deployment
and a Service, the node and etcd member names are per box, and the data stays in
`/var/lib/k0s`. Joining (vNext) will need: a join token from the first box, the other boxes started
as workers or as controllers for a three-member etcd, each box's etcd peer address moved from
`198.18.0.1` to an address the others can reach (an etcd member update, done in place), and the
edge, storage and backup design that section lists. The one-member etcd costs memory (roughly 100
to 200 MB resident) and an fsync on every write; on SD cards that's the concern, and the arm64 run
measures it.

## Where its data lives

Everything k0s writes is under `/var/lib/k0s` on the state volume (LUKS2, mounted at `/var/lib` by
init): etcd, the PKI, containerd's image store and snapshots (`containerd/`), the binaries k0s
unpacks (`bin/`), the kubelet's directory, the image links (`images/`) and the stacks
(`manifests/`). The CNI files are in `/var/lib/cni-conf` and `/var/lib/opt`, the plugins containerd runs in
`/var/lib/sneakers/k0s/cni-bin`, and the host-local IP allocations in `/var/lib/cni`. The rendered config and k0s's run directory are on `/run` (tmpfs).
`k0s-interim prepare` keeps its record in `/var/lib/sneakers/k0s/prepare.log`, so a failed
pre-start survives a reboot even though the console log is on tmpfs: one line per step,
`<UTC time> [<pid>] <message>`, from `prepare starts` to `prepare done`, or
`prepare failed at the step "<step>" (exit N)` from its EXIT trap. The pid tells two runs apart.
Past 64 KiB it rolls over to `prepare.log.1`.
A factory reset wipes them with the rest of the state.

## The product bundle and the airgapped images

The installed bundle's current slot, `/var/lib/sneakers/product/current` (a link to `a` or `b`),
holds `k0s`, `helm` (when its `release.yaml` pins one), `release.yaml`, `images/` (one OCI archive per pinned image, each named by its digest,
with its signature beside it) and `manifests/` ([release.md](release.md#the-product-bundle)). The
box checked all of it before it linked the slot. At every start `k0s-interim prepare` links each
archive into `/var/lib/k0s/images/`, which k0s imports into containerd when the worker starts, so
the images aren't copied again. A link the slot also has is replaced by rename, a new one is made
under a dot name first, and one the slot lacks is removed (a link already gone counts as
removed), so k0s never finds a half-made link and the step doesn't fail on a link that changed
under it. Each archive
names its image `<image>@sha256:<digest>`, which is the name the kubelet asks for when a pod's
image is `<image>:<tag>@sha256:<digest>`. With the pull policy `Never`, a pod whose image isn't
bundled fails with `ErrImageNeverPull` instead of reaching for a registry.

Each `manifests/<stack>/` goes to `/var/lib/k0s/manifests/<stack>/`, which k0s applies, with the
box's own values in place of the placeholders the bundle declares (`<slot>/box-values`, from
product.yaml `box_values`): the values recorded in `/var/lib/sneakers/platform/box-values` (the FQDN,
else the kernel's host name, and the Base OS and Base Web versions init records at boot;
[release.md](release.md#productyaml)) ([network.md](network.md#the-host-name)). When the
bundle exposes values ([release.md](release.md#productyaml)), the slot also holds the RBAC the box
rendered for them, `exposed-rbac.yaml`, and `prepare` puts it in the stack
`sneakers-appliance-exposed`; with none, that stack goes and k0s deletes what it held.

### kubectl and helm in the root shell

The root shell ([ssh-and-elevation.md](ssh-and-elevation.md#the-root-shell)) reaches the installed
k0s with no setup. `/usr/bin/kubectl` links to the current slot's `k0s`, which acts as kubectl when
it's run by that name, and `/usr/bin/helm` links to the slot's `helm`, so both follow the slot after
an apply or a revert. With a product installed the shell starts with
`KUBECONFIG=/var/lib/k0s/pki/admin.conf`, k0s's admin kubeconfig. It stays where k0s
wrote it, and nothing copies it. helm keeps its cache and settings under `/tmp/helm` (the root is
read-only), so they go at a reboot. With no product installed the shell says once at its start "No
product is installed; kubectl and helm come with it.", and both links dangle. helm is pinned in
`release.yaml` like k0s (`spec.kubernetes.helm`: the version and each architecture's SHA-256), and the
box refuses a bundle whose helm doesn't match the pin, or that carries a helm its `release.yaml`
doesn't pin. Lab builds take `HELM_VERSION` from `build/ci/versions.env`, with the upstream tarball
checked against its published SHA-256. A production bundle carries helm once sneakers-release's
`release.yaml` pins it.

`helm list -A` is empty by design: the appliance applies the product's stacks as k0s manifests, not
Helm releases, because the update slots and revert track the manifests directly, and Helm's release
state would sit outside them. The root shell's `help` says so.

For k0s v1.36.4+k0s.1 the components left on need five images: pause, kube-proxy, CoreDNS,
kube-router and its CNI installer (`cni-node`). A lab build pins them, the hello image and the
edge's Traefik in `build/lab/images.txt` and signs each digest with that run's lab key. `os/k0s/config_test.go`
fails when the config, the containerd sandbox and the lab list disagree. A production release
takes its images from sneakers-release's `release.yaml`, which doesn't list k0s's images yet.

## The hello-world stack and the interim edge (lab, throwaway)

Lab product bundles only (`build/lab/stacks`), applied by k0s from `/var/lib/k0s/manifests/`:

- `hello` runs busybox's httpd in the `sneakers-hello` namespace, as nobody with a read-only root,
  and serves a page saying `hello from sneakers-appliance`, which loads the box-state poller, on
  NodePort 30080. It goes when platformd lands (#99).
- `edge` is a minimal edge, **interim until Traefik comes with the platform (#102)**: Traefik on the
  host network in the `sneakers-edge` namespace, with every capability dropped but
  `NET_BIND_SERVICE`. It serves `https://<box>/` on 443 from the hello NodePort, and 80 redirects to
  https. TLS uses the certificate assigned to the Product (443) endpoint, else the box's own :8443
  one, which `k0s-interim prepare` writes as the `box-tls` Secret at each start and the
  Certificates page writes live ([certificates.md](certificates.md#applying)); Traefik reads the
  routes and that certificate from one watched directory (the `edge` ConfigMap and the Secret's
  `traefik-tls.yaml`), so a new one needs no restart, and falls back to its own self-signed default
  without it. Traefik's ping has its own entry point on `127.0.0.1:9000`, as spec 3 has it, and the
  readiness probe gets `http://127.0.0.1:9000/ping` there. Ping can't share 443: Traefik's ping
  router has no TLS, so over HTTPS the hello route's `PathPrefix(/)` took `/ping` and answered 404.
- The edge also serves the product's Ingresses: Traefik's kubernetesingress provider reads the
  Ingresses of the class `traefik` (the stack's IngressClass, the cluster default) in the
  `sneakers` namespace, under its own service account with a read-only cluster role (nodes, services,
  secrets, EndpointSlices, Ingresses and IngressClasses, plus the Ingress status). Every router on
  443 terminates TLS, so an Ingress without a `tls` block gets `box-tls` as well. The hello route
  has priority 1, so a product Ingress for `/` wins over it whenever one exists. Traefik reaches
  the pods from the host network, from the node address: a product NetworkPolicy must admit it by
  `ipBlock` (a `namespaceSelector` doesn't match host-network traffic).
- The edge's `oauth-prefix` middleware strips `/oauth` from the paths the product's OAuth issuer
  routes (Hydra's Ingress on `/oauth/.well-known/`, `/oauth/oauth2/` and `/oauth/userinfo`) forward ([network.md](network.md#the-host-name)).
- The edge routes `/_box/` (priority 1000, ahead of the hello route and the Ingresses) to sneakers-edgefall on
  `127.0.0.1:9180`, and the hello route's `box-page` middleware serves edgefall's box-state page for
  `502` to `504`. The hello page loads `/_box/poll.js`, so an open tab shows "Sneakers-PAM is
  rebooting" and the like through a reboot, a shutdown or an update, and comes back by itself; while
  k0s is down edgefall answers 80 and 443 itself ([edge-fallback.md](edge-fallback.md)). Traefik's
  start command asks edgefall for 80 and 443 right before it execs `traefik`, so they're held
  until then rather than refused while k0s brings the edge up.
- Once a bundle is installed, accessd opens 80 and 443 on the service interface (the management
  one when the box has only one) through netd's `SetServicePorts`, after each product apply and
  revert and when it starts. 22 and 8443 are as before. Before a bundle is installed nothing
  listens on 80 or 443.

## The kernel

The kernel has everything built in, so what k0s, containerd, the kubelet, kube-proxy and
kube-router need is in `os/kernel/config-base`: cgroup v2 and namespaces, overlayfs, veth, the
bridge and `br_netfilter`, VXLAN, netfilter (nftables, the iptables compatibility layer, conntrack,
NAT, ipset), plus inotify, POSIX timers, file handles, shebang scripts, PSI, conntrack over
netlink, NFLOG, the ipset, limit, physdev and MARK matches and targets, REJECT, the nftables
limit, log and reject expressions, and the dummy interface. `os/kernel/required.txt` fails the build without the ones k0s
can't start without.

## Testing

`os/k0s/prepare_test.go` runs the whole `k0s-interim prepare` against a fake box under a
temporary root (ip and mount faked; the box's busybox with `SNEAKERS_TEST_BUSYBOX`, else
`/bin/sh`): the bundle before phases, then the phased Sneakers bundle's slot layout
(phase-stacks, switch-stacks, box-values, the exposed RBAC) applied into the other slot; a
failure naming its step in the record; the record's rollover; and the image links made by two
runs at once. `internal/services/onestart_test.go` checks that the supervisor never runs a
pre-start twice at once: a Start during a pre-start, a product apply (Stop, then Start) during a
restart's backoff, and many Stop and Start rounds in a row.

`test/image/k0s` (the image suite, after each merge and nightly; it isn't run on pull requests)
boots a lab disk without Secure Boot or a TPM and sets it up the whole way: the console wizard, the
first admin's key over SSH, a recovery key and the first :8443 sign-in. In normal operation it
checks that k0s waits (no product bundle, no k0s) and that 443 doesn't answer, then installs the
lab product bundle through the Updates API (`POST /upload`, `StageUpdate`, `ApplyUpdate` with
target product). The lab image's hook (`build/lab/overlay/.../lab-hook`) does nothing unless the
ESP holds a `lab-hook` file, which only the suite writes: then it reports on the serial line (the
console service owns the consoles) whether k0s ran before a bundle was installed, and waits for the
bundle, the API, the node, the hello pod, the box saying running (edgefall's `/_box/state` on
127.0.0.1:9180, which says so only once the phase loop has brought every phase up) and the edge
pod. It samples the phase pods only then: after a power loss the first Ready hello pod is the old
one, restarted in place by the kubelet before the box quiesced it. After three minutes of waiting it
prints, once, the pods, the routes and the addresses. The test then fetches `https://<box>/` from
the host through QEMU's port forward and expects the hello text, checks that 80 redirects to
https, that SSH and :8443 still answer, that `GetUpgrades` shows the installed product running,
and that k0s doesn't crash-loop. After a power loss it boots the box again and checks the hook's
phase pods line (every phased pod Ready with no restarts, the front phase started only once the
data phase was Ready, and none is a pod the first install started: the box quiesced those and
started new ones), logs its scaling events line (the quiesce, then each phase) and checks its
sandbox events line (no FailedCreatePodSandBox event with the CNI
plugin's "exec: already started"). The lab bundle is the one the lab build writes next to the disk
(`SNEAKERS_PRODUCT`). Its MCP switch (on by default) gates `lab-mcp`, which is Ready only while
hello answers, placed with the front phase. A second run installs the same product as a bundle
without phases (`SNEAKERS_PRODUCT_UNPHASED`, `build/lab/unphased.sh`, never published), then the
phased one: the box quiesces every unlabelled workload, `lab-mcp` included, and brings the phases
up in order. The hook samples the phases only once the installed product has them.
