# SSH and elevation

SSH on the box is key-only. Every admin logs in with their own name into the closed shell; real
shell access is a one-time elevation through a short-lived certificate for the `maint` account.

## sshd's configuration

accessd renders sshd's files from the access store into a staging directory; `sneakers-sshd-run`
checks them with the pinned `sshd -t` and swaps them into `/run/sneakers/ssh/` only when sshd
accepts them. A config that fails the check is never used, and the previous one stays.

| File | Contents |
|---|---|
| `sshd_config` | the settings below |
| `authorized_keys/<admin>` | each of the admin's keys, prefixed `restrict,pty`: no forwarding, no user rc, and a pty for the interactive shell |
| `principals/maint` | the `elev-<id>` principal of each approved, unused elevation |

The global settings:

- `AuthenticationMethods publickey`; password, keyboard-interactive and empty-password logins are
  off, and so is `PermitRootLogin`.
- `DisableForwarding yes`, `PermitTunnel no`, `PermitUserRC no`, `PermitUserEnvironment no`, and no
  `Subsystem` line, so there is no sftp or scp.
- `ForceCommand /usr/bin/sneakers-shell` and `ExposeAuthInfo yes`, so the closed shell learns which
  key signed in.
- `RevokedKeys /var/lib/sneakers/ssh/revoked.krl` for removed login keys and used elevation
  certificates.
- `AllowUsers` lists the admins and `maint` (and `enrol` while an enrolment window is open); in the
  first-boot enrolment step it lists only `enrol`.
- The algorithms are the modern set only: ed25519, ECDSA P-256 and P-384, the FIDO forms of ed25519
  and P-256, RSA with SHA-2 signatures, and their certificate types; ML-KEM and sntrup761 hybrid key
  exchange or curve25519; ChaCha20-Poly1305 and AES-GCM; encrypt-then-MAC SHA-2 MACs.

`Match User maint` trusts the appliance's user CA only for that account, takes principals from
`principals/maint`, forces `/usr/libexec/sneakers-elevated` and allows one session per connection.
`Match User enrol`, rendered only during an enrolment window, accepts any key through
`sneakers-enrol-keys` and forces `sneakers-enrol`, which then needs the code and the console's `yes`
([The enrolment window](#the-enrolment-window)).

The tests render every mode and run the pinned static sshd's `sshd -t` on each; the Static tools
workflow runs them with `SNEAKERS_TEST_SSHD` pointing at the binary it built.

## The closed shell

`sneakers-shell` is every admin's login shell and sshd's `ForceCommand`. It offers only the appliance
commands below, interactively (with `help`, line editing and tab completion) or one per connection
through the SSH command line:

```sh
ssh alice@192.0.2.10 status -o json
ssh alice@192.0.2.10 keys add < new.pub
```

The shell splits the line itself; nothing is passed to `/bin/sh`, and the binary links nothing that
can start a program. Spaces and tabs separate words, single quotes keep everything to the next single
quote, double quotes keep everything to the next unescaped double quote (`\"` and `\\` are the only
escapes inside them), and a backslash outside quotes keeps the next character. `$`, `` ` ``, `;`,
`|`, `&`, `<`, `>`, `*` and `?` are ordinary characters: `status; id` is the unknown command
`status;`. A line longer than 64 KiB, with an open quote, a trailing backslash, invalid UTF-8 or a
control character is refused with `SHELL_PARSE`; an unknown command is `SHELL_UNKNOWN`.

| Command | Console | SSH | In this release |
|---|---|---|---|
| `status` | yes | yes | accessd |
| `network show`, `network set key=value...`, `network confirm <token>` | yes | yes | accessd; `set` reverts in 120 s unless kept |
| `network allow-list reset` | yes | no | accessd; typed `reset` |
| `keys list`, `keys add`, `keys remove <fingerprint>` | yes | yes | accessd; `add` reads the key from standard input |
| `admins list`, `admins add <name>`, `admins remove <name>` | yes | yes | accessd; owners only |
| `recovery-key add` | yes | no | accessd |
| `setup recovery-key` | no | yes | accessd; first boot only |
| `login <code>` | no | yes | accessd: approves a :8443 sign-in |
| `shell --minutes N --reason "..."`, `elevation status [<id>]`, `elevation cert <id>` | no | yes | accessd; see [One-time elevation](#one-time-elevation) |
| `tls show`, `backup ...`, `restore ...`, `upgrade ...`, `mcp ...`, `resources ...` | yes | yes | Not available in this release |
| `logs export`, `support-bundle` | no | yes | Not available in this release |
| `reboot`, `poweroff` | yes | yes | init, over `/run/sneakers/power.sock`; typed `reboot` or `poweroff`; always graceful |

A command offered only in the other origin is refused with `ACCESS_FORBIDDEN` and isn't listed by
`help` or completed. `-o json` prints a command's result, or its error as
`{"error": {"code", "number", "message"}}`. The commands of later specs answer `NOT_AVAILABLE`
("Not available in this release.") until their services are on the box. The accessd commands go to
`/run/sneakers/access.sock`, which knows the login by its uid ([access.md](access.md#accesssock));
`network set` takes `hostname`, `dns`, `search`, `ntp`, `allow-list` (comma-separated lists),
`time-zone` and `https-proxy` on top of the current settings. While accessd is down they answer
`NOT_AVAILABLE` ("the appliance services are unavailable"), and `status` shows the last status
accessd kept, with the time it was taken.

### Signing in to :8443

`login XXXX-XXXX` asks accessd (`LocalService.DescribeSignIn` on `/run/sneakers/access.sock`)
which browser is waiting on the code and asks:

```text
Sign in the browser at 192.0.2.50 (Mozilla/5.0 ...) as alice? [y/N]
```

Only `y` or `yes` approves; anything else, including an empty line, doesn't. The browser's address
and user agent are shown with control characters replaced and cut to 200 characters, so a crafted
user agent can't rewrite the terminal. On `y` the shell calls `LocalService.ApproveSignIn` with the
admin, the client's address (from `SSH_CONNECTION`) and the fingerprint of the key that signed in
(from the `SSH_USER_AUTH` file sshd writes with `ExposeAuthInfo`). osadmin checks the caller's uid is
that admin and the key is theirs, and audits the approval either way. A session whose key sshd didn't
name can't approve a sign-in.

## The enrolment window

The first admin's keys (first-boot step 3), and more keys later through the console, come in over
SSH while the console watches:

1. The console opens a window for one admin (`EnrolmentService.OpenEnrolment`, root only). accessd
   makes the SSH host keys if the box has none (`ssh_host_ed25519_key` and a 3072-bit
   `ssh_host_rsa_key` in `/var/lib/sneakers/ssh/`, mode 0600) and returns their fingerprints and an
   enrolment code, `XXXX-XXXX`. The `enrol` account (uid 103) now exists in the rendered passwd, and
   sshd's `Match User enrol` block is rendered.
2. The admin checks the host key fingerprint and runs `ssh enrol@<address>`. sshd's
   `AuthorizedKeysCommand`, `sneakers-enrol-keys %f %k %t` (run as `sshkeys`), prints the offered
   key back with `restrict` when its type is an accepted login key type and the fingerprint, key
   and type agree, so any such key authenticates as `enrol`.
3. `sneakers-enrol`, the forced command, asks for the code and sends it with the key sshd
   authenticated (from `SSH_USER_AUTH`) and the client address. accessd lets the enrol uid make
   only these calls. A wrong code says how many attempts are left; the third closes the window and
   a new one opens with a new code on the console. Nothing the client types besides the code does
   anything.
4. The console shows the key (fingerprint, type, comment, address); typing `yes`
   (`AcceptEnrolmentKey`) stores it as the admin's key, `via` `enrol`. `sneakers-enrol` waits for
   that answer and prints "Key enrolled", or that the console refused it.
5. The window closes when the console presses Done (`CloseEnrolment`), after 30 minutes without a
   code, a key or an answer, or after three wrong codes. The `enrol` account and its sshd block go
   away with it, so outside a window `ssh enrol@` is refused at authentication.

Every step is in the OS audit log (`enrol.open`, `enrol.code`, `enrol.submit`, `enrol.accept`,
`enrol.reject`, `enrol.close`).

## One-time elevation

A real root shell is a one-time elevation: a short-lived OpenSSH certificate for the `maint`
account, signed by the box's own user CA after an owner approves.

1. **Request.** `shell --minutes 30 --reason "investigate kubelet"` (15 to the policy's maximum,
   240 by default; 0 or no `--minutes` takes the default of 60) records the admin, the key the
   login signed in with, its SSH client address, the reason and the length, and prints a request id
   such as `E-7K2Q`. The shell then waits and prints the certificate once it is approved; Ctrl-C
   withdraws the request (audited, and it can't be approved afterwards), and so does closing the
   connection while it waits. A request nobody approves expires after 30 minutes (`ELEV_EXPIRED`).
2. **Approve.** An owner approves on the Shell elevation page (`ApproveElevation`, with a step-up)
   or on the console, optionally shortening it (never lengthening it, `ELEV_MINUTES`), or denies it.
   - With two or more owners, nobody approves their own request (`ELEV_SELF_APPROVAL`).
   - With one owner, that owner may, and the request is flagged `self_approved`: in the audit entry,
     on the page and on Status (`WARNING_KIND_SELF_APPROVED_ELEVATION`) while it is approved or
     active. Turning `selfApprovalWhenSingleOwner` off in the elevation policy refuses it too.
   - An owner whose key came through the console's Recover access can't approve for 24 hours
     (`ELEV_HOLD`).
   - Admins (not owners) can't approve (`ACCESS_FORBIDDEN`).
3. **Certificate.** On approval accessd signs a user certificate for the requester's own key:
   principal `elev-<id>`, key id `elev-<id> admin=<name> fp=<fingerprint>`, the next serial, valid
   from now for 10 minutes (the window to connect, not the session's length), critical options
   `force-command=/usr/libexec/sneakers-elevated` and `source-address=<the request's address>`,
   and the one extension `permit-pty`. `elev-<id>` joins `principals/maint`.
4. **Fetch.** The waiting `shell` prints it, or `elevation cert E-7K2Q > ~/.ssh/id_ed25519-cert.pub`
   does. Only the requester gets it.
5. **Connect.** `ssh -i ~/.ssh/id_ed25519 maint@192.0.2.10`, from the address the request came
   from, within the 10 minutes.
6. **Single use.** Before it gives a prompt, `sneakers-elevated` has accessd use the certificate
   up (`BeginElevatedSession`): the request goes active, `elev-<id>` leaves `principals/maint` and
   the serial joins `revoked.krl`, so a second connection with the same certificate fails at
   authentication. If accessd can't be reached, no shell starts.
7. **Session.** `sneakers-elevated` runs `/bin/sh -l` (static busybox) as root on a pty it owns,
   records both directions to `os-audit/sessions/<id>.cast` with the chunk hashes in the OS audit
   log ([os-audit.md](os-audit.md#session-recordings)), shows the minutes left in the prompt, warns
   at 5 and 1 minutes, and ends the shell's whole process group at the approved length. An owner
   can terminate it from the page or the console (`TerminateElevation`): accessd sends
   `sneakers-elevated` a `SIGTERM`, after checking the pid is still one. Terminating an approved
   certificate nobody has used yet revokes it.
8. **End.** `sneakers-elevated` reports how the session ended (`exit`, `time-box` or
   `terminated`) and the SHA-256 of the whole recording. Owners read the recording on the page
   (`GetElevationRecording`), checked against the logged chunk hashes.

While a session is active, the automatic update window waits for it to end, and an owner's Apply or
Revert on the Updates page is refused with `UPGRADE_ELEVATED`, naming the admin and the request:
the session ends, or an owner terminates it, before the box goes down. An owner can also end it
from the refusal with the typed override ([upgrades.md](upgrades.md)), which terminates the
session, audited with the reason, and applies once its end is reported. While an update is being
applied or reverted (from the moment the apply starts until the box reboots, at most 15 minutes if
the reboot never comes; a failed apply ends it at once), a new request, an approval and the first
connection with an approved certificate are refused with `ELEV_MAINTENANCE`.

### The user CA, the serials and the revocation list

| File in `/var/lib/sneakers/ssh/` | Contents |
|---|---|
| `user_ca.pub` | the ed25519 user CA's public key; sshd trusts it for `maint` only. The private key isn't kept here: it's the sealed item `ssh-user-ca` (below) |
| `serial` | the last certificate serial issued, written before each certificate is signed |
| `revoked.krl` | an OpenSSH key revocation list of every serial used, expired or revoked and every removed login key not un-revoked ([access.md](access.md#removed-keys-are-revoked)), rewritten on each change; sshd reads it as `RevokedKeys` |
| `/var/lib/sneakers/access/elevation.json` | the requests and what became of them: the history the page shows |

The CA signs only elevation certificates, in process (`golang.org/x/crypto/ssh`), and is trusted
only in the `maint` block. It never signs host or login certificates.

**Sealed CA:** accessd makes the CA at its first start and seals the private key through init's
`KeyCustody.Seal("ssh-user-ca")`, so in TPM mode a copied state volume doesn't yield it; every start
unseals it. A box set up before this kept the CA as a plain `user_ca` key file (0600, root); accessd
seals that same key, checks the sealed copy reads back, then overwrites and removes the file, so the
CA (and the certificates it signed) stays the same. If the seal fails the file is left and accessd
doesn't start.
