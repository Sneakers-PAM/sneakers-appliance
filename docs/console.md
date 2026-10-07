# The console

The box's console is the screen (VGA, `tty0`) and the serial line (`ttyS0`), whichever the box
has; init joins them ([init.md](init.md#the-console)), so everything below shows on both and either
one can answer. Two programs own the console in turn:

| Phase | Program | Service entry |
|---|---|---|
| `firstboot` | `sneakers-firstboot`: the setup wizard | `services.d/firstboot.yaml` |
| `normal` | `sneakers-console`: the status view and the menu | `services.d/console.yaml` |

Both run as root, after accessd, with `console: true` in their entry: their output reaches every
console while every other service's lines (and init's own) go to `/run/sneakers/console.log`
(1 MiB, then `console.log.1`), which the menu's **Recent messages** shows. When the program stops,
the shared output comes back on the consoles; init restarts it. Before either runs, init's own
screens (the Secure Boot choice in `enrol`, the at-rest protection step, "State locked") are
unchanged.

## How it looks

Every page fits an 80x24 terminal (and so 80x25 and wider): a header with the box's host name, the
reduced-protection banner when it applies, the body, the keys that work, the prompt, and a footer
with the version, the phase, the time (UTC) and whether NTP is synced. Pages are drawn with cursor
addressing and redrawn row by row, so a clock tick rewrites one row, nothing flickers, and an
answer typed half-way stays where it is.

Colour is foreground only (no backgrounds or reverse video), and nothing depends on it: alerts
start with `!!` or `!`. `sneakers.console=plain` on the kernel command line, or `TERM=dumb`, turns
colour off. Input is a line at a time (type, then Enter): the consoles stay in the kernel's line
mode, which works the same on a VMware screen and a serial line.

When protection is reduced, every page starts with it, in plain words and with how to raise it:

```
 !! Protection: reduced (Secure Boot off). Someone with the disk or SD card
    can change this box's software and read its data.
    Raise it later on the :8443 Status page (Secure Boot on); no reinstall.
```

The same sentences are on :8443's Status page (the reduced-protection warning) and in the wizard's
protection step, from one source (`internal/consoleui/screens`).

## The setup wizard

The steps of first boot, in order, with a step strip on every page
(`[x] 1 Network  [>] 2 Protection  [ ] 3 Admin  [ ] 4 Recovery  [ ] 5 Sign-in`):

1. **Network.** netd takes an address by itself on its first start (DHCP and SLAAC on the first
   linked NIC); the wizard shows it, and Enter keeps it once the checks pass. **e** chooses instead:
   the interfaces (name, MAC, link, driver); with no link on any, it waits for one.
   Then the management interface (22 and 8443 listen only there) and, with two NICs, the service
   interface; then the settings, each changed by its number: IPv4 (DHCP, static, off), IPv6 (SLAAC,
   DHCPv6, static, off), host name, DNS and NTP, validated as typed. Enter applies them live and
   runs the checks (link, address, gateway, DNS, NTP). A failed check can be skipped (**c**,
   continue anyway), except no address on the management interface; **e** edits. Keeping the
   settings confirms netd's 120-second auto-revert.
2. **Protection.** Read-only: the Secure Boot choice and the key custody were made at boot, by
   init, before the wizard (the state volumes are formatted for them). The page says the level, the
   at-rest key, and how to raise a reduced level later.
3. **First admin.** The owner's name (checked against the name rules and the reserved names), then
   netd opens port 22, sshd starts and the enrolment window opens ([ssh-and-elevation.md](ssh-and-elevation.md#the-enrolment-window)):
   the page shows `ssh enrol@<address>`, the code, the host key fingerprints, and the keys enrolled
   so far. A key that gave the code is shown with its fingerprint and stored only on a typed `yes`.
   **t** types a key on the console; **f** fetches an `authorized_keys` file over https (no
   redirect to http), and each key found is confirmed with its own `yes`. **d** (Done, after one
   key) closes the window.
4. and 5. **Continue on :8443.** netd opens port 8443 and osadmin starts once step 3 is done. The page shows the :8443 URLs,
   the certificate's SHA-256 fingerprint to check on the first visit, and the recovery keys set so
   far (one to three, added on the :8443 setup page or with `setup recovery-key` over SSH). It
   moves on by itself once :8443 finishes setup after the first sign-in.
6. **Complete.** The product's first-run URL, then normal operation.

Steps 4 and 5 complete as the box shows them done: a recovery key set, then the first :8443 sign-in
(recorded by :8443 when the first session starts). With one admin the wizard then shows the
single-admin warning (no quorum, so a factory reset means re-creating the box) and needs `one admin`
typed to go on. Then it calls accessd's `Setup.Complete`, which checks every step again (an owner
with a key, a recovery key and its escrow, the first sign-in, the warning confirmed) and writes
`/var/lib/sneakers/setup/done`.

### The step machine

`internal/setup` keeps the progress: the steps `network`, `protection`, `admin`, `recovery`,
`signin` and `done`, completed in that order only (anything else is `SETUP_INCOMPLETE`, naming the
open step), in `progress.json` written with an atomic rename. Until the protection step it's on
the tmpfs (`/run/sneakers/setup/`), so a power cut there runs the network step again; from the
protection step on it's on the state volume (`/var/lib/sneakers/setup/`), and the tmpfs copy is
removed. After a power cut or a restart of the wizard, it resumes at the first step not done. A
progress file that doesn't parse stops the wizard rather than run steps again on a box that may be
set up.

accessd reads the same file for the access store's invariants: no owner with a key is required
until the admin step is done (first boot adds its owner before the key), and no recovery key until
the recovery step is; once `setup/done` exists every invariant applies.

## The status view

```
 Version      0.1.0 (stable channel), slot A
 Secure Boot  enforcing, org keys only         At rest   TPM
 Platform     running                          Upgrades  none staged
 Management   192.0.2.10/24  2001:db8::10/64
 :8443        https://192.0.2.10:8443/  (self-signed: check the fingerprint)
              3F:A1:...  (the certificate's SHA-256, in full, on two lines)
 SSH host     ssh-ed25519  SHA256:...
              ssh-rsa      SHA256:...

 ! The clock isn't synchronised with an NTP server.
```

It reads :8443's Status data from accessd (or, while accessd is down, its last saved copy, with
the time it was saved), the protection and the custody mode from init, the root slot from init's
environment and the host keys from the state volume, every 5 seconds. The warnings are Status's
(the exposure warning, NTP, a key added with Recover access, a self-approved elevation), a factory
reset pending or counting down (who started it, the time left, and **c** on the menu to cancel
it), and any component that isn't answering. During an upgrade the maintenance view replaces it.

Enter opens the menu; a console command can also be typed straight at the prompt (`keys list`).

## The menu

The console commands of the closed shell's console origin, from the shell's own command table
([ssh-and-elevation.md](ssh-and-elevation.md#the-closed-shell)), so the console and SSH can't drift
apart: `status`, `network show`, `network set`, `network confirm`, `network allow-list reset` (the
console's lockout recovery), `keys list`, `keys add`, `keys remove`, `admins list`, `admins add`,
`admins remove`, `recovery-key add`, `tls show`, `backup`, `restore`, `upgrade`, `mcp`,
`resources`, `reboot` and `poweroff`. A command that takes arguments asks for them first; one that
reads a key asks for it on one line; each typed confirmation (`reboot`, `reset`) is asked by the
command itself. The output shows as the command's transcript, as plain text.

Then the console's own entries:

- **Recover access**, for when every admin key is lost: type an owner's name to add a key to them,
  or a new name to make a new owner. It runs the enrolment window as above, marked as a recovery:
  each key stored is recorded in the OS audit log as `access.console-recovery`, every other owner
  sees the warning on :8443 Status while the hold lasts, and the key can't approve elevations for
  24 hours (`approvalHoldUntil`; another owner can lift it).
- **Recent messages**: the tail of `/run/sneakers/console.log`.
- **Cancel the factory reset**, while one is pending or counting down (typed `cancel`).

## What isn't in this build yet

The console names a missing backend plainly ("... isn't installed in this build yet") and never
shows a success it didn't get. Each switches to the real one when its service is in the service
table, with no change to the console:

| Backend | Until it's in the build |
|---|---|
| netd or sshd, on a build without them | the interface list is read from sysfs (an interface not brought up shows `not up`) and the network step can't apply settings, so it stops there; the enrolment window says `ssh enrol@` can't connect, and keys are typed or fetched on the console |
| moving to normal while init runs | setup completes and writes `setup/done`; normal operation starts on the next boot (the complete page offers `reboot`) |
| the platform (spec 3) and the upgrade service (spec 5) | the status view says the platform isn't installed; upgrades show only the staged and rolled-back versions from Status |

The fetch over https uses the system CA bundle; the root image carries none yet, so a fetch fails
with the TLS error until it does, and typing the key works.
