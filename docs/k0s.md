# k0s on the box

The appliance runs one k0s node: the controller with its worker (`k0s controller --enable-worker
--no-taints`), a one-member etcd, kube-router for the pod network and kube-proxy in iptables mode.
It starts in normal operation only, from the images bundled in the root, with no registry to
reach.

**Interim.** Until `sneakers-platformd` lands (#99, spec 3), the service table starts k0s through
a small script, `os/k0s/k0s-interim`, which stands in for platformd: it prepares the box and
starts k0s. Lab builds also carry a throwaway hello-world stack. platformd replaces the script,
renders the config and deploys the real platform; the hello stack goes then.

## What runs

| Piece | Where | What |
|---|---|---|
| Service entry | `os/rootfs/services.d/k0s.yaml` | `k0s-interim run` (`exec`s `k0s controller --enable-worker --no-taints --config /run/sneakers/k0s/k0s.yaml --data-dir /var/lib/k0s`), root, `restart: always`, `stop-timeout: 2m`, after netd, phase `normal` only (the data directory is on the state volume). konnectivity, metrics-server, autopilot and the update prober are disabled: none is bundled, and the prober would reach the internet. While the console service owns the consoles, k0s's output goes to `/run/sneakers/console.log`. |
| Pre-start (interim) | `k0s-interim prepare` (`/usr/libexec/sneakers/k0s-interim`) | mounts cgroup2 on `/sys/fs/cgroup` when it isn't; makes the box's node name once (below); gives the kernel a host name when it has none; makes `/var/lib/sneakers/machine-id` once; puts `198.18.0.1/32` on the `sneakers0` dummy interface and routes the Service range there (below); renders the config into `/run/sneakers/k0s/`; makes the CNI and log directories; writes an empty `/run/sneakers/resolv.conf` if netd hasn't written one; links the bundled images into `/var/lib/k0s/images/`; copies each stack in `/usr/share/sneakers/manifests/<name>/` to `/var/lib/k0s/manifests/<name>/` |
| Cluster config | `/etc/k0s/k0s.yaml.tmpl` (`os/k0s/k0s.yaml.tmpl`) | the API, etcd peer and node address `198.18.0.1`; the pod range `10.244.0.0/16` and the Service range `10.96.0.0/12` (k0s's defaults, named, and the defaults of the box's network settings, [network.md](network.md)); every system image pinned by `<tag>@sha256:<digest>`; `default_pull_policy: Never`; NodePorts on every address; telemetry off; etcd storage named `@NODE_NAME@`, the one field rendered <!-- scrub:allow=private-ip --> |
| containerd config | `/etc/k0s/containerd.toml` (`os/k0s/containerd.toml`) | what k0s would write, with the sandbox (pause) image pinned by digest. It isn't marked `k0s_managed`, so k0s uses it as it is instead of writing into the read-only `/etc`. Drop-ins: `/etc/k0s/containerd.d/` (empty). |
| Host paths in the root | the root | `/etc/cni -> /var/lib/cni-conf` and `/opt -> /var/lib/opt` (kube-router installs the CNI config and plugins there), `/var/run -> /run` (containerd's NRI socket), `/var/log -> /var/lib/log` (pod logs), `/etc/machine-id -> /var/lib/sneakers/machine-id`, `/etc/hosts` (localhost), `/bin/mount` and `/bin/umount` (busybox; the kubelet mounts tmpfs volumes with them), `/lib/modules` (empty: the kernel has no loadable modules), `/usr/libexec/k0s/kubelet-plugins/volume/exec` (empty) |

k0s runs etcd, the API server and the scheduler as root here: the box has no `etcd`,
`kube-apiserver` or `kube-scheduler` accounts, and k0s falls back to root when it can't find them.

### The node's address and name

The node's address is `198.18.0.1` on `sneakers0` (spec 3: RFC 2544 space, never routed), so a
DHCP change on a real interface never changes the API server's certificates, etcd's peer address
or the node's address. Its name, `sneakers-<8 hex>`, is made once from a random UUID and kept in
`/var/lib/sneakers/k0s/node-name`. It's the kubelet's node name (`--hostname-override`) and the
etcd member name, and it doesn't follow the host name netd sets, so it stays the same across
reboots and upgrades and is unique when more boxes join.

The Service range is routed on `sneakers0` too. kube-proxy reaches a ClusterIP by rewriting it
(DNAT) on the way out, but the kernel looks up a route before that rewrite, so a host with no
route covering the ClusterIP fails `connect()` with "network is unreachable". kube-router talks to
the API through the `kubernetes` Service, so on a management network with no gateway
(a static address without one, or QEMU's restricted user network in the image suite) it never
started, and with it the pod network: pods stayed in ContainerCreating on the bridge CNI's "no IP
ranges". With the route the cluster doesn't depend on the management network's gateway, the same
as its address.

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
(`manifests/`). The CNI files are in `/var/lib/cni-conf` and `/var/lib/opt`, and the host-local IP
allocations in `/var/lib/cni`. The rendered config and k0s's run directory are on `/run` (tmpfs).
A factory reset wipes them with the rest of the state.

## The airgapped images

The root carries the bundle in `/usr/share/sneakers/images/` ([root-image.md](root-image.md)): one
OCI archive per pinned image, each named by its digest, with its signature beside it. At every
start `k0s-interim prepare` links each archive into `/var/lib/k0s/images/`, which k0s imports into
containerd when the worker starts, so the images aren't copied onto the state volume. Each archive
names its image `<image>@sha256:<digest>`, which is the name the kubelet asks for when a pod's
image is `<image>:<tag>@sha256:<digest>`. With the pull policy `Never`, a pod whose image isn't
bundled fails with `ErrImageNeverPull` instead of reaching for a registry.

For k0s v1.36.4+k0s.1 the components left on need five images: pause, kube-proxy, CoreDNS,
kube-router and its CNI installer (`cni-node`). A lab build pins them, and the hello image, in
`build/lab/images.txt` and signs each digest with that run's lab key. `os/k0s/config_test.go`
fails when the config, the containerd sandbox and the lab list disagree. A production release
takes its images from sneakers-release's `release.yaml`, which doesn't list k0s's images yet.

## The hello-world stack (lab, throwaway)

Lab builds only (`build/lab/overlay`): `/usr/share/sneakers/manifests/hello/hello.yaml`, applied by
k0s from `/var/lib/k0s/manifests/hello/`. It runs busybox's httpd in the `sneakers-hello`
namespace, as nobody with a read-only root, and serves `hello from sneakers-appliance` on NodePort
30080. The management firewall doesn't open that port. It goes when platformd lands (#99).

## The kernel

The kernel has everything built in, so what k0s, containerd, the kubelet, kube-proxy and
kube-router need is in `os/kernel/config-base`: cgroup v2 and namespaces, overlayfs, veth, the
bridge and `br_netfilter`, VXLAN, netfilter (nftables, the iptables compatibility layer, conntrack,
NAT, ipset), plus inotify, POSIX timers, file handles, shebang scripts, PSI, conntrack over
netlink, NFLOG, the ipset, limit, physdev and MARK matches and targets, REJECT, the nftables
limit, log and reject expressions, and the dummy interface. `os/kernel/required.txt` fails the build without the ones k0s
can't start without.

## Testing

`test/image/k0s` (the image suite, after each merge and nightly) boots a lab disk without Secure
Boot or a TPM, through first boot, and then in normal operation. The lab image's hook
(`build/lab/overlay/.../lab-hook`) does nothing unless the ESP holds a `lab-hook` file, which only
the suite writes: then it marks setup done in first boot, and in normal operation it waits for the
API, the node to be Ready and the hello pod to be Ready, then fetches the NodePort from inside the
pod and prints what it got, on the serial line (the console service owns the consoles). After
three minutes of waiting it prints, once, the pods, kube-router's and kube-proxy's logs, the
routes, the addresses and kube-proxy's NAT rules for the `kubernetes` Service. The test checks those
lines, fetches the NodePort from the host through QEMU's port forward, and checks that k0s doesn't
crash-loop; it skips the general crash-loop check, since services that need the skipped first-boot
steps (sshd with no owner key) keep failing there. It needs KVM: under software emulation k0s
takes many minutes to get its API up.
