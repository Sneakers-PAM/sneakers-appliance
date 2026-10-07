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
- `RevokedKeys /var/lib/sneakers/ssh/revoked.krl` for removed keys and used elevation certificates.
- `AllowUsers` lists the admins and `maint` (and `enrol` while an enrolment window is open); in the
  first-boot enrolment step it lists only `enrol`.
- The algorithms are the modern set only: ed25519, ECDSA P-256 and P-384, the FIDO forms of ed25519
  and P-256, RSA with SHA-2 signatures, and their certificate types; ML-KEM and sntrup761 hybrid key
  exchange or curve25519; ChaCha20-Poly1305 and AES-GCM; encrypt-then-MAC SHA-2 MACs.

`Match User maint` trusts the appliance's user CA only for that account, takes principals from
`principals/maint`, forces `/usr/libexec/sneakers-elevated` and allows one session per connection.
`Match User enrol`, rendered only during an enrolment window, accepts any key through
`sneakers-enrol-keys` and forces `sneakers-enrol`, which then needs the code and the console's `yes`.

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
| `login <code>` | no | yes | osadmin: approves a :8443 sign-in |
| `shell --minutes N --reason "..."`, `elevation status [<id>]`, `elevation cert <id>` | no | yes | accessd |
| `tls show`, `backup ...`, `restore ...`, `upgrade ...`, `mcp ...`, `resources ...` | yes | yes | Not available in this release |
| `logs export`, `support-bundle` | no | yes | Not available in this release |
| `reboot`, `poweroff` | yes | yes | init, over `/run/sneakers/power.sock`; typed `reboot` or `poweroff`; always graceful |

A command offered only in the other origin is refused with `ACCESS_FORBIDDEN` and isn't listed by
`help` or completed. `-o json` prints a command's result, or its error as
`{"error": {"code", "number", "message"}}`. The commands of later specs answer `NOT_AVAILABLE`
("Not available in this release.") until their services are on the box. The accessd commands answer
`NOT_AVAILABLE` ("the appliance services are unavailable") until accessd's socket is there.

### Signing in to :8443

`login XXXX-XXXX` asks osadmin (`LocalService.DescribeSignIn` on `/run/sneakers/osadmin.sock`)
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
