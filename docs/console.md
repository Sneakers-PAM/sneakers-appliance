# The console

The box's console is the screen (VGA, `tty0`) and the serial line (`ttyS0`), whichever the box
has; init joins them ([init.md](init.md#the-console)), so everything below shows on both and either
one can answer. The console shows information. Setup and everyday admin work happen on the :8443
admin page; the console never asks for an SSH key, a typed `yes` or a "done" key. Two programs own
the console in turn:

| Phase | Program | Service entry |
|---|---|---|
| `firstboot` | `sneakers-firstboot`: the start-up and the setup info screen | `services.d/firstboot.yaml` |
| `normal` | `sneakers-console`: the status screen and Recover access | `services.d/console.yaml` |

Both run as root, after accessd, with `console: true` in their entry: their output reaches every
console while every other service's lines (and init's own) go to `/run/sneakers/console.log`
(1 MiB, then `console.log.1`). When the program stops, the shared output comes back on the
consoles; init restarts it. Before either runs, the screen shows init's starting page ("Sneakers-PAM
is starting") and none of the kernel's, init's or the services' lines; init's own screens (the
Secure Boot choice in `enrol`, the at-rest protection step, "State locked") clear it and show as
before. A reboot or a shutdown puts "Sneakers-PAM is rebooting" or "Sneakers-PAM is shutting down"
on the screen until the power goes ([init.md](init.md#the-screen-stays-quiet)). The serial line
still shows every line.

The only inputs left are:

- the network editor, shown only when DHCP gives the box no address;
- **Recover access**, the break-glass way back in when no admin can sign in;
- **C** to cancel a factory reset that is counting down, and **X** to stop a browser setup that
  isn't yours.

## The font and the screen size

The kernel has the Terminus 16x32 font built in (`CONFIG_FONT_TER16x32`), and the UKI's command
line selects it (`fbcon=font:TER16x32`). On VMware's default 1024x768 that gives a 64x24 console,
large enough to read the setup code and the fingerprints from across a desk. The 8x16 font
(`CONFIG_FONT_8x16`) stays built in as the fallback: when the large font leaves the screen
smaller than 64x24 (a framebuffer below 1024x768), the console switches the screen to `VGA8x16`
(the `KDFONTOP` ioctl on `tty0`) before it draws.

The screens are laid out for the real terminal: the console reads each active console's size
(`TIOCGWINSZ`) and uses the smallest that reports one. A serial line reports none and doesn't
count; with no size at all the console uses 80x24. The same output goes to every console, so it has
to fit the smallest.

## How it looks

Every screen is a frame round the whole terminal, every row the full width and ending in the same
column, with a body block of at most 56 columns centred in it. A row is always written in full, so
a redraw needs no erase that would clear the frame's right edge. The start-up and the setup info
screens carry the Sneakers-PAM mark (the sneaker with the keyhole), the wordmark and, on its own dim
line under it, the version; the others have a one-row header with a small mark, the wordmark, the version, the slot
and the node count, and the keys in a dim row at the bottom, each ruled off. Keys are single
letters or digits, typed and then Enter (the consoles stay in the kernel's line mode, which works
the same on a VMware screen and a serial line); a screen with nothing to type hides the cursor.
The arrows, Home, End, the page and function keys do nothing: init turns `ECHOCTL` off on each
console, so they aren't echoed as `^[[C`, and their escape sequences (CSI, SS3 and the VT's
`ESC [ [ A` to `E`) are taken out of the typed line. A line of nothing but such keys is dropped, so
an arrow and Enter never pick a default, at init's own screens too. Back is Enter on an empty line,
`0`, `b`, `back` or Esc, wherever a screen offers it.

```
+--------------------------------------------------------------+
|                                                              |
|                       .------.                               |
|                      /  .-.   \ = = =                        |
|                     |  ( o )   '------._                     |
|                     |   |_|            '\                    |
|                    (=====================)                   |
|                                                              |
|                    Sneakers-PAM Appliance                    |
|                            0.1.0                             |
|                                                              |
|   Open this address in your browser:                         |
|      https://192.0.2.10:8443                                 |
|                                                              |
|   Certificate fingerprint                                    |
|      7C2E 91AB 4F06 D3E8 B15A 6C90 2E7F 0A4D                 |
|      E38B 5C21 9FD0 76A4 C1E9 0B3F 8D62 A7C5                 |
|                                                              |
|   Setup code  7PQK-NMS9-XD2A-4KJW   expires in 59 min        |
|                                                              |
|   Protection  REDUCED  no TPM, no Secure Boot                |
|                                                              |
|                                                              |
+--------------------------------------------------------------+
```

Colour is the brand palette in the console's 16 colours, foreground only (no backgrounds or
reverse video):

| What | SGR | VT slot | Colour |
|---|---|---|---|
| The frame and the mark | `34` | 4 | the primary blue `#2F5BD3` |
| The keyhole | `1;34` | 12 | the bright blue `#7FA3F0` |
| The setup code and the mark's sole (the one accent) | `33` | 3 | the approved orange `#E8742A` |
| OK, a warning, danger | `1;32`, `1;33`, `1;31` | 10, 11, 9 | green `#6FD39B`, yellow `#F2C04B`, red `#F06B5F` |
| Secondary text | `2` | 8 (half-bright) | dim grey `#8B94A6` |
| What is read aloud or typed | `1;37` | 15 | bold white `#FFFFFF` |

The VT's default palette is VGA's, where slot 3 is brown (`#AA5500`), so the UKI's command line
loads the palette above into the VT (`vt.default_red=`, `vt.default_grn=`, `vt.default_blu=`, 16
values each, from `tui.Palette`); the slots no style uses keep VGA's colours. It applies to the
screen only: a serial terminal keeps its own palette, where `33` is whatever it calls yellow.

Nothing depends on colour: every status is a word (`OK`, `REDUCED`, `UNSYNCED`) and every warning
starts with `!`. `sneakers.console=plain` on the kernel command line, or `TERM=dumb`, turns colour
off. Fingerprints are written in groups of four, eight groups to a line, so they can be read aloud.

## First boot

`sneakers-firstboot` asks for nothing while DHCP works:

1. **Starting.** The mark, then the start-up steps: the system image verified, the encrypted data
   disk, the network (with the time it has waited) and the setup page.
2. **Network.** netd takes an address by itself on its first start (DHCP and SLAAC on the first
   linked NIC). As soon as the box has one, the network step is done. When none comes within 30
   seconds, the console shows the ports (name, cable, hardware address) with **N** (set an address
   by hand) and **R** (try DHCP again). The editor takes one field at a time: the port (with more
   than one), the address with its prefix, the gateway and the DNS server (both optional), with
   **B** to go back. Enter applies it live and shows netd's checks; Enter again keeps it (confirming
   netd's auto-revert), **E** edits. A failed check that can't be skipped holds it back.
3. **Protection** was chosen at boot from the hardware; the step completes by itself and the info
   screen shows the level in one line.
4. **Ready to set up.** netd opens port 8443 (not 22) and osadmin starts. The screen shows the
   :8443 address on each management address (and, directly under it, on the box's FQDN once a
   hostname or domain is set), the certificate's SHA-256 fingerprint to check on the first visit,
   the one-time setup code (`XXXX-XXXX-XXXX-XXXX`, 16 Crockford base32 characters, the sole
   orange; [access.md](access.md#the-8443-setup-page)) with the minutes it has left of its 60, and
   the protection. A new code replaces it
   when it lapses, and the screen redraws at once.
5. **Setting up.** Once a browser has typed the code, the screen shows where it's from, when it
   started and the step it's at. Until the first admin exists, **X** stops that setup and shows a
   new code. When the first admin exists, netd opens port 22 and sshd starts. A code locked by 5
   wrong tries shows `LOCKED`; **N** asks for a new one.
6. **Done.** When :8443 finishes setup, the box moves to normal operation: at once when init can,
   otherwise it says so and restarts once, by itself.

The console reads all of this from the access backend's console API (`sources.ConsoleAccess`:
the setup code, its expiry and tries left, the :8443 addresses and certificate, setup's state,
step and source, the first admin, a code locked by wrong tries, and a live Recover access code):
`GetConsoleInfo` for each read, and `WatchConsoleInfo` so the screen redraws as soon as anything
changes. `ResetSetupCode` asks for a new code (X, and N on a locked code).

### The step machine

`internal/setup` keeps the progress: the steps `network`, `protection`, `admin`, `recovery`,
`signin` and `done`, completed in that order only (anything else is `SETUP_INCOMPLETE`, naming the
open step), in `progress.json` written with an atomic rename. Until the protection step it's on
the tmpfs (`/run/sneakers/setup/`), so a power cut there runs the network step again; from the
protection step on it's on the state volume (`/var/lib/sneakers/setup/`), and the tmpfs copy is
removed. After a power cut or a restart of first boot, it resumes at the first step not done. A
progress file that doesn't parse stops first boot rather than run steps again on a box that may be
set up.

The console completes the network and protection steps itself, and follows :8443 for the rest: the
admin step once the first admin exists, the recovery step once a recovery key is set, the sign-in
step after the first sign-in. Then, once a single admin has been confirmed on the page, it calls
accessd's `Setup.Complete`, which checks every step again and writes `setup/done`.

accessd reads the same file for the access store's invariants; once `setup/done` exists every
invariant applies.

## The status screen

```
+--------------------------------------------------------------+
|  /o\__  Sneakers-PAM Appliance   0.1.0  slot A  1 node       |
+--------------------------------------------------------------+
|                                                              |
|   Health        OK      all services running                 |
|   Base          OK      0.1.0 in slot A; 0.0.9 to go back    |
|   Product       OK      0.1.0-lab.hello.1 running            |
|   Protection    FULL    Secure Boot on, key in the TPM       |
|   Clock         OK      synced 18:03 UTC                     |
|                                                              |
|   Admin         https://192.0.2.10:8443                      |
|                 https://sneakers.example.org:8443            |
|   SSH           192.0.2.10:22                                |
|                 key from :8443 Access, then TOTP             |
|                                                              |
|   Fingerprints                                               |
|     :8443   7C2E 91AB 4F06 D3E8 B15A 6C90 2E7F 0A4D          |
|             E38B 5C21 9FD0 76A4 C1E9 0B3F 8D62 A7C5          |
|     ssh     SHA256:yskn evuN I/Ng 13w+ vvxl QW6F             |
|                    cH76 LnuV dAfL HqOr ZRw                   |
|                                                              |
+--------------------------------------------------------------+
|  R  Recover access                                           |
+--------------------------------------------------------------+
```

It reads :8443's Status data from accessd (or, while accessd is down, its last saved copy, with the
time it was saved), the protection and the custody mode from init, the root slot from init's
environment, the host keys from the state volume and the node count from the platform, every 5
seconds. In order: health, the base, the product, protection and the clock, each a status word in
its colour with the details dim; the admin page on the first management address and, on the line under it, on
the box's FQDN once one is set; SSH on port 22, with a dim line under it saying the key comes from
:8443's Access page and a TOTP code follows ([ssh-and-elevation.md](ssh-and-elevation.md#the-first-ssh-login)); the fingerprints of the page's
certificate and the SSH host key; then the warnings, each a `!` in its colour with its first
sentence in bold. The warnings are Status's own (the exposure warning, a self-approved elevation
and the like, but not the ones with their own line: reduced protection, the clock and the
self-signed certificate), an upgrade staged, reverted by an admin ("Reverted from 0.1.1 by alice at
14:05 UTC", in the plain colour) or rolled back by boot counting, a factory reset waiting for approval or
counting down (with **C** to cancel it), a Recover access code that's out, a service that isn't
answering, and accessd itself not answering. Without a management address the screen offers **N**,
the network editor. A failed update step is a warning for a day ("The update to 0.1.1 failed.",
then the step and why), from Status's `upgrade_progress`. A reboot that never came is one: after
10 minutes on the same boot the update fails at Rebooting with `UPGRADE_NO_REBOOT` and the
maintenance screen gives way to this one.
When the body doesn't fit the screen, its blank rows go first (from the top), so the warnings are
cut only when there's no other room.

**Base** is the release running and its slot, with what's staged ("0.1.0 in slot A; 0.1.1 staged")
or else the release kept to go back to ("; 0.0.9 to go back"), from Status. **Product** is the
product bundle, from Status's `product` slots until platformd is in the build:

| Word | When | Details |
|---|---|---|
| `NONE` (dim) | no bundle installed | "installed from the admin page, Updates", or "0.2.0 staged; install it from Updates" |
| `OK` | the installed version runs | "0.1.0 running", then "; 0.2.0 staged" or "; 0.0.9 to go back" |
| `STOPPED` | installed, but k0s isn't running | "0.1.0 isn't running" |
| `FAILED` | a product update failed in the last day | "the update to 0.2.0 failed" (the warning says which step and why) |
| `UNKNOWN` | no status yet | "no status yet" |

During a stage, an apply or a revert (Status's `upgrade_progress` with `in_progress`) the
maintenance screen replaces it. It says what's happening ("Staging 0.1.1. The box keeps running.",
"Updating to 0.1.1. Leave it powered on." or "Going back to 0.0.9. Leave it powered on.") and lists
the steps ([upgrades.md](upgrades.md#the-steps-of-an-update)), each marked `[ok]` done, `[..]` the
current one (in bold, with what it's doing or waiting for under it), `[  ]` still to come, or
`[!!]` failed:

```text
Updating to 0.1.1. Leave it powered on.

  [ok]  Verifying (signature, channel, SHA-256)
  [ok]  Staging into slot B
  [ok]  Switching slots
  [ok]  Rebooting
  [..]  Checking health
        Waiting for netd to answer: connection refused
  [  ]  Marking good

If 0.1.1 doesn't come up healthy, the box goes back to 0.1.0 by itself.
```

While the release is written into the slot the current step has a progress bar, the percentage
and the sizes (`[##########----------]  50%  700.0 MB of 1.4 GB`). The steps after the reboot come
from the release the box booted, so the screen is back on the new release's console for checking
health and marking good, and gives way to the status view once the update is done. **R** (Recover
access) still works.

A product apply says "Installing the product 0.2.0. The box keeps running." (a revert "Going back
to the product 0.1.0. The box keeps running."), and has no fallback line: the box doesn't revert a
product by itself. It stays on the screen while the product comes up, until 443 answers with it
([upgrades.md](upgrades.md#the-product-coming-up)):

```text
Installing the product 0.2.0. The box keeps running.

  [ok]  Verifying (signature, channel, SHA-256)
  [ok]  Staging into the free product slot
  [ok]  Switching slots
  [ok]  Restarting the product
  [ok]  Starting k0s
  [ok]  Importing the images
  [ok]  Applying the product's stacks
  [..]  Waiting for the pods to be ready
        2 of 5 pods ready
  [  ]  Opening the product on 443
```

## Recover access

**R**, for when no admin can sign in. It's recorded, and every admin sees a notice the next time
they sign in. **0** (or Enter) goes back:

1. **Let this network reach the admin page again**: resets who can connect (accessd's
   `ResetAllowList`) to the management network. The screen asks to check the admin page opens from
   there, then **K** keeps the change; otherwise it's put back by itself.
2. **Reset an owner's sign-in with a one-time code** (`BeginRecoverAccess`): the screen shows
   `https://<address>:8443/recover`, the certificate to check and the code, in the setup code's
   form (`XXXX-XXXX-XXXX-XXXX`, sealed and destroyed on use). On :8443 it opens only setup step 2: a new password and
   authenticator for an owner, or a new owner. It works once, for 60 minutes and 5 tries; **C**
   withdraws it.

## What isn't in this build yet

The console names a missing backend plainly ("... isn't installed in this build yet") and never
shows a success it didn't get. Each switches to the real one when it's in the build, with no change
to the screens:

| Backend | Until it's in the build |
|---|---|
| netd, on a build without it | first boot skips the network step and the screens say the address isn't known |
| moving to normal while init runs | setup completes and the box restarts once into normal operation |
| the platform (spec 3) | Product reads the product's slots from Status, and the node count is 1 |
