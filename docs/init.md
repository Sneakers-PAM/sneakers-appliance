# sneakers-init

`sneakers-init` is PID 1 on the box. It decides the boot phase, unlocks the state, and supervises
the service table. There's no systemd.

## Boot phases

Decided on every boot from what the firmware reports and the recorded Secure Boot choice (the
LUKS2 header once first boot fixed it, the ESP's `loader/sneakers/secure-boot` before that):

| Facts | Phase |
|---|---|
| booted from the install medium | `install` |
| the ESP's `reset.json` records a factory reset that isn't done (or doesn't read) | `reset`: init finishes the reset, starts nothing, and reboots into first boot ([factory-reset.md](factory-reset.md)) |
| set to Secure Boot on, past enrolment, and the firmware doesn't enforce (or no longer has Secure Boot variables) | `mismatch`: the console shows the mismatch screen and nothing starts |
| no Secure Boot firmware, or Secure Boot off by choice | `firstboot`, or `normal` once setup is done |
| Secure Boot firmware and no choice yet, or on but not enforcing with org-only keys (including turned on later, before the keys are enrolled) | `enrol` |
| on, enforcing, org-only keys | `firstboot`, or `normal` once setup is done |

`firstboot` runs until `/var/lib/sneakers/setup/done` exists; init then moves to `normal` without a
reboot.

## The service table

One YAML file per service in `/usr/lib/sneakers/services.d/<name>.yaml` (read-only root):

```yaml
exec: /usr/bin/k0s                 # absolute path
args: [controller, --enable-worker]
phases: [normal]                   # install, enrol, firstboot, normal
after: [platformd]                 # started once these are ready
restart: always                    # always, on-failure (default) or never
readiness:                         # a file that appears, or a command that exits 0
  file: /run/sneakers/k0s.ready
  timeout: 2m
start: always                      # always (default) or on-demand
on-demand-in: [firstboot]          # phases, among phases:, where it waits to be asked
user: osadmin                      # a fixed unprivileged system account; default root
capabilities: [net-bind-service]   # ambient capabilities kept with user:; only this one
pre-start: [/usr/libexec/sneakers/platformd, prepare]
stop-timeout: 2m                   # SIGTERM to SIGKILL; default 10s
start-when: [/var/lib/sneakers/setup/done]  # absolute paths that must all exist first
```

- Entering a phase stops the services that don't run in it and starts the `start: always` ones that
  do, in `after:` order, each once its dependencies are ready.
- `start: on-demand` services start and stop only when asked (the Services API), and only in
  their phases. `on-demand-in` makes an always-start service on-demand in the phases it lists
  (osadmin waits for its first-boot step and starts with the normal phase).
- `start-when` holds a `start: always` service back until every path it lists exists. Entering the
  phase, a service with a missing path isn't started: its status says `SERVICE_WAITING` and names
  the path, and init looks again every 5 seconds and starts it once they all exist. The Services
  API starts a waiting service at once, whatever its paths, and stops it; a service stopped that
  way stays stopped until it's started again. k0s waits for `setup/done` (the first admin exists)
  and an installed product bundle ([k0s.md](k0s.md)).
- `user` runs the service as one of the fixed system accounts that has its own uid (`sshd`,
  `sshkeys`, `osadmin`, `edgefall`), with no supplementary groups; any other name is
  `SERVICE_TABLE_INVALID`. Init never falls back to root for such an entry.
- `capabilities` lists ambient capabilities a `user` service keeps. The only one allowed is
  `net-bind-service` (`CAP_NET_BIND_SERVICE`), which sneakers-edgefall needs for 80 and 443
  ([edge-fallback.md](edge-fallback.md)); any other, or one without `user`, is
  `SERVICE_TABLE_INVALID`.
- The root image's table lives in `os/rootfs/services.d/` (accessd as root, osadmin as `osadmin`;
  see [access.md](access.md#accessd)).
- `pre-start` runs to completion before every start; a non-zero exit keeps the service from
  starting (`SERVICE_PRE_START`) and its restart policy decides whether it's tried again.
- A service that exits is restarted by its policy with a backoff from 1 to 30 seconds. Stopping
  sends SIGTERM, then SIGKILL after the entry's `stop-timeout` (10 seconds when unset). k0s sets
  a longer one so it can stop its workloads cleanly.
- A drain (a graceful reboot or shutdown, or a factory reset) stops the services in reverse
  `after:` order, so k0s stops before platformd, and nothing starts again until the box reboots.
  A reboot's or a shutdown's drain leaves `edgefall` running until the power goes, so 443 shows
  the box-state page once k0s has stopped ([edge-fallback.md](edge-fallback.md)).
- An entry that doesn't parse, an unknown `after:` name or a loop is `SERVICE_TABLE_INVALID`, and
  the table isn't used.

## init.sock

Init serves its local API (Connect, which also speaks the gRPC protocol) on `/run/sneakers/init.sock` (proto
`proto/sneakers/appliance/init/v1/init.proto`, generated into `gen/go` by
`scripts/proto-generate.sh`). The socket is mode 0600, and every connection's peer is read with
`SO_PEERCRED`: anyone but root is refused before a request is read. The services are
`KeyCustodyService`, `PlatformService`, `ImageService`, `PowerService` and `ServicesService`; the
ones whose bodies later work adds answer `Unimplemented` until then. `KeyCustodyService` serves
`Mode`, `Protection`, `Seal`, `Unseal` and `Escrow` over the custody init unlocked
([key-custody.md](key-custody.md#the-keycustody-service)). `ImageService` serves `Status`,
`Stage`, `Activate`, `MarkGood` and `Rollback` from the image stager once the state is unlocked and
the ESP is mounted ([upgrades.md](upgrades.md)). `ServicesService` starts, stops and
reports the table's on-demand services and the ones with `start-when`.

`PowerService` (reboot, power-off, and arming, cancelling and running the factory reset) is also
served alone on `/run/sneakers/power.sock`, mode 0666 in a searchable `/run/sneakers`, which admits
root and the admin uids, so the
closed shell's logins can reboot. On both sockets it answers only `sneakers-accessd` (the :8443
API's backend; `sneakers-osadmin` runs unprivileged and can't reach either socket) and
`sneakers-shell`, told apart by the peer's executable, and the factory reset only accessd. See
[factory-reset.md](factory-reset.md) for what each request does.

## PID 1

Init mounts `/proc`, `/sys`, `/dev`, devpts on `/dev/pts`, `/run`, `/tmp` and efivarfs, and mounts
the ESP at `/run/sneakers/esp`. devpts is where the kernel finds the terminals `/dev/ptmx` hands
out: without it sshd can't give an SSH login a terminal, and the root shell can't open one. Unless it booted from the install medium or is finishing a factory reset, it
then reads the custody header on the state volume, unlocks and mounts state and backup (or, on
first boot, runs the protection step and makes them), all before the service table
([key-custody.md](key-custody.md#at-boot)); a state that doesn't unlock stops the boot with the
reason on the console. One loop reaps every child (init inherits every orphan) and hands each exit
status to whatever started it, so services run without `os/exec`'s own waiting. The tools init
runs itself (cryptsetup and mkfs.ext4 for the state volumes) go through it too, with their input
and output on pipes: `os/exec`'s wait would race the loop and fail with `ECHILD`. On the console it
prints `sneakers-init: phase=<phase> protection=<level>`. In `enrol` it runs the Secure Boot screens
([secure-boot.md](secure-boot.md)): on QEMU and Proxmox it reboots by itself after enrolling; on
VMware and bare metal it waits for the admin's power cycle. In `mismatch` it shows the mismatch
screen and starts nothing. In `reset` it finishes an interrupted factory reset before anything
starts. SIGTERM stops every service and syncs the disks.

### The console

Right after the early mounts, init reads the kernel's active consoles
(`/sys/class/tty/console/active`, `tty0 ttyS0` on the appliance), opens each, and leaves out any
that refuses a zero-length write: a serial port with no UART behind it fails every write with EIO.
Its log names the consoles it kept (`init: console consoles=tty0`) and each one left out, with the
reason. Standard output and error become a pipe that init copies to every console kept, so init's
banner, the Secure Boot screens and every service's output show on the screen and on the serial
line alike. Each console has its own queue, so a stuck serial line can't stop the screen. Standard
input is a pipe fed by every console, so the Secure Boot choice can be typed on whichever one the
admin has. Before it reboots or powers off, init waits up to two seconds for the last lines to
reach every console. When no console takes writes, init keeps the console the kernel gave it.

A service with `console: true` owns the consoles while it runs (the first-boot info screen in
`firstboot`, the status screen in `normal`; [console.md](console.md)): its standard output is its own pipe, copied
to every console, while init's and every other service's output goes to
`/run/sneakers/console.log` instead (1 MiB, then `console.log.1`). At most one service per phase may
own the console, and it runs as root. When it stops, the consoles get a fresh line with the colours
reset and the shared output again.

#### The screen stays quiet

The screen (a VT: `tty0`) never shows the kernel's, init's or the services' lines; the serial line
still does, and they all go to `/run/sneakers/console.log` too. The UKI's command line has
`quiet loglevel=1`, and init writes `1 4 1 7` to `/proc/sys/kernel/printk` right after the early
mounts, so only the kernel's emergencies reach a console (the rest stay in the kernel log). Then
init puts a branded page on the screen, the mark with "Sneakers-PAM is starting", and keeps the
shared output off it. Its own screens that ask on the console (the Secure Boot choice, the
protection step, "State locked", the mismatch screen, a fatal error) clear the screen and show as
before; once they're answered the starting page comes back. A console program draws over it as
soon as it owns the consoles.

When a reboot or a shutdown is accepted, before the drain, init writes `rebooting` or
`shutting-down` to `/run/sneakers/box-state` (mode 0644; the product edge's box-state page reads it
through accessd's `GetPhase` and sneakers-edgefall, [edge-fallback.md](edge-fallback.md)), then puts
"Sneakers-PAM is rebooting" or "Sneakers-PAM is shutting down" on the screen and holds it there: nothing else reaches the screen,
not even the console program's last frames, until the power goes. The finished factory reset at
boot, and the enrol phase's reboot on QEMU, show the rebooting page the same way.
