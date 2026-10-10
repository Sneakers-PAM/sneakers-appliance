# SSH and elevation

SSH on the box takes only keys the box issued. Every admin logs in with their own name into the
closed shell and gives a TOTP code first; a root shell is opened through a one-time challenge and a
code from :8443. There are no SSH password logins, no admin-supplied login keys, no operator
(client) certificates and no recovery codes in this release.

### The first SSH login

SSH needs a key from :8443 first, and sshd takes it only with its certificate. A client without
one is refused with `No supported authentication methods available (server sent: publickey)`,
after the banner below.

1. Sign in to :8443 (name, password and TOTP code), open **Access** and choose **Get an SSH key**
   (it asks for a fresh TOTP code). The box keeps neither the private key nor any of the files.
   Each key has three downloads, all named after the key's serial so they always pair and a
   browser never adds " (1)": `id_ed25519_<name>_sneakers_<serial>` (the OpenSSH private key),
   `<that>-cert.pub` (its certificate), `<that>.ppk` (the same key for PuTTY and MobaXterm, with
   the certificate in it), `<that>.pem` (the same key as PEM PKCS#8, for other tools; use it with
   the `-cert.pub`) and `<that>.pub` (the public key all three share).
2. Log in with your own name, sending the certificate with the key:
   - **OpenSSH:** `ssh -i <key> -o CertificateFile=<key>-cert.pub <name>@192.0.2.10`. OpenSSH
     also finds the certificate on its own when it sits next to the key under exactly
     `<key>-cert.pub`; the `CertificateFile` option makes it explicit.
   - **PuTTY 0.78 or later:** use the `.ppk` download (Connection > SSH > Auth > Credentials,
     "Private key file for authentication"). To build one yourself from the OpenSSH pair: in
     PuTTYgen, Conversions > Import key, then Key > Add certificate to key, then Save private key;
     or keep the key and set Connection > SSH > Auth > Credentials > "Certificate to use".
     Earlier PuTTY releases can't read a certificate and are refused.
   - **MobaXterm:** Session (or User sessions > New session), then SSH; Remote host: the box's
     address; Username: your admin name; Port: 22. Under Advanced SSH settings tick "Use private
     key" and browse to the box's `.ppk`. Connect. MobaXterm reads PPK format 3 since v21.5 and
     has its own certificate field (expert settings) since v25.1; use v25.1 or later.
3. The closed shell asks for a TOTP code, under the same lockout as :8443, then shows the menu for
   your role.

There is no way to skip the TOTP code on SSH and no SSH password login: the key is one factor and
the code the other. A bare box-issued key, sent without its certificate, is never accepted: sshd
refuses it, and `sneakers-sshd-run` audits the refusal (below), so :8443's audit log shows why the
login failed.

## sshd's configuration

accessd and `sneakers-sshd-run` render sshd's files from the access store into a staging directory,
check them with the pinned `sshd -t` and swap them into `/run/sneakers/ssh/` only when sshd accepts
them (`sshconfig.Install`, under an flock on `/run/sneakers/ssh.lock`). Beside `sshd_config` it
writes `banner`, which sshd sends before authentication (`Banner`): SSH takes only keys the box
issued, each with its certificate, then a TOTP code; a key comes from :8443, Access, "Get an SSH
key"; and it gives the OpenSSH command with `-o CertificateFile=<key>-cert.pub` and the PuTTY and
MobaXterm way (the `.ppk`). A config that fails the check
is never used, and the previous one stays.

- `AuthenticationMethods publickey`, `AuthorizedKeysFile none` and `TrustedUserCAKeys
  /var/lib/sneakers/ssh/root_key.pub`: the only keys sshd takes are certificates the box's root key
  signed for the admin's name ([access.md](access.md#issued-ssh-keys)). Password,
  keyboard-interactive and empty-password logins are off, and so is `PermitRootLogin`.
- `RevokedKeys /var/lib/sneakers/ssh/revoked.krl`: removed keys, as keys and as certificate serials.
- `HostCertificate /var/lib/sneakers/ssh/ssh_host_<kind>_key-cert.pub` for each host key that has
  one: a host certificate signed by the box's SSH host CA (below), offered first
  (`HostKeyAlgorithms` lists the certificate types before the bare keys).
- `DisableForwarding yes`, `PermitTunnel no`, `PermitUserRC no`, `PermitUserEnvironment no`, and no
  `Subsystem` line, so there is no sftp or scp.
- `ForceCommand /usr/bin/sneakers-shell` and `ExposeAuthInfo yes`, so the closed shell learns which
  key signed in.
- `AllowUsers` lists the admins who can sign in; with none, `DenyUsers *`.
- The algorithms are the modern set only: ed25519, ECDSA P-256 and P-384, RSA with SHA-2 signatures,
  and their certificate types; ML-KEM and sntrup761 hybrid key exchange or curve25519;
  ChaCha20-Poly1305 and AES-GCM; encrypt-then-MAC SHA-2 MACs.

### The host CA and the known_hosts line

The box has two SSH CAs. The user CA is the root key ([access.md](access.md#issued-ssh-keys)),
which signs the admins' certificates. The host CA is a key of its own, made at accessd's first start
and sealed through KeyCustody like the root key (`host-ca-key`), with its public half in
`/var/lib/sneakers/ssh/host_ca.pub`. accessd signs a host certificate for each host key with it
(`ssh_host_ed25519_key-cert.pub`, `ssh_host_rsa_key-cert.pub`), for the box's host name and its
management addresses (link-local ones left out), valid for a year. It signs them again whenever it
renders sshd's files and the host key, the names or the addresses changed (netd's address and host
name events re-render), or in a certificate's last 30 days, and then tells sshd to reload.

A client that trusts the host CA never sees a host key prompt. Both CA public keys are in the
`IssueSshKey` answer and in `ListAdmins` (`user_ca_public_key`, and `known_hosts` with
`known_hosts_file_name` on the key download, `host_ca` on Access): the known_hosts line is

```text
@cert-authority box1.sneakers.example.org,192.0.2.10 ssh-ed25519 AAAA... sneakers-appliance host CA
```

Add it to `~/.ssh/known_hosts` (or point `-o UserKnownHostsFile=` at the downloaded file), and
`ssh -o StrictHostKeyChecking=yes` connects with no prompt; a host certificate from any other CA is
refused.

The tests run the pinned static sshd's `sshd -t` on the rendered config, and
`TestRealSshdTakesOnlyTheRootKeysCertificates` logs in against it: a certificate from the root key
works, a plain key or another CA's certificate doesn't, and a revoked serial is refused.
`TestRealSshdPresentsItsHostCertificate` connects with only the `@cert-authority` line in
known_hosts and strict host key checking, with Go's client and, when `SNEAKERS_TEST_SSH` names
OpenSSH's `ssh`, with that too; a line for another CA is refused.
`TestRealSshdAuditsABareIssuedKey` sends an issued key without its certificate and checks the
audit entry. The Static tools workflow runs them with `SNEAKERS_TEST_SSHD` pointing at the binary
it built.

### A key without its certificate

sshd's log (`LogLevel VERBOSE`, on `sneakers-sshd-run`'s stderr) passes through a watch on its way
out. For each `Failed publickey for <user> from <address> ... ssh2: ED25519 SHA256:<fingerprint>`
line whose fingerprint is a box-issued key in the access store, it writes an OS audit entry:
action `ssh.login`, outcome `refused`, code `ACCESS_KEY_NO_CERTIFICATE`, the login name as the
actor, the source address, the key's fingerprint, the key's owner as the target and its serial.
A certificate that's refused (expired, revoked, for another name) logs as `ED25519-CERT` and isn't
counted here, and neither is a key the box never issued. The log itself is passed on unchanged.

## sneakers-sshd-run

sshd runs under `sneakers-sshd-run --config-dir /run/sneakers/ssh` (`os/rootfs/services.d/sshd.yaml`:
in first boot accessd asks init to start it once the first admin exists, and at its own start when an
admin can sign in; always in normal operation, after netd and accessd, restarted whenever it stops).
It:

1. reads the access store and exits with `ACCESS_NO_ADMIN` while no admin can sign in;
2. waits until netd reports a management address, then renders, checks with `sshd -t` and swaps the
   files in;
3. writes its pid to `/run/sneakers/sshd.pid` and runs `sshd -D -e -f /run/sneakers/ssh/sshd_config`
   as its child (sshd's own `PidFile` is `none`), so every reload passes `sshd -t` first;
4. on a `SIGHUP` (accessd sends one when `sshd_config` changed) or a new address list on netd's
   `Watch` stream, renders and checks again, and sends sshd a `SIGHUP` only when the check passed and
   the config changed. A render sshd refuses is logged and audited (`sshd.config`, outcome
   `refused`); sshd keeps the config it has;
5. on `SIGTERM` stops sshd (`SIGTERM`, then `SIGKILL` after 10 seconds); when sshd exits on its own
   sshd-run exits with it and init restarts both.

Flags: `--config-dir`, `--state` (`/var/lib/sneakers`), `--sshd` (`/usr/sbin/sshd`), `--netd-socket`
and `--pid-file` (`/run/sneakers/sshd.pid`).

## The closed shell

`sneakers-shell` is every admin's login shell and sshd's `ForceCommand`. It first asks for a TOTP
code (`SshLoginService.VerifyTotp`, under the same lockout as :8443 sign-in,
[access.md](access.md#lockout-and-throttling)) and closes the connection when it is wrong or the
account is locked; then it offers only the appliance commands below, interactively (with `help`, line editing and tab completion) or one per connection
through the SSH command line:

```sh
ssh alice@192.0.2.10 status -o json
```

The interactive shell needs a terminal; without one it takes only a command on the SSH command line.

Tab completes the word before the cursor from the command tree's own completion (cobra's): the
commands and subcommands, the flags (`--admin`, `-o`), and the values the shell knows: the
`network set` keys (`time-zone=` and so on; a key already on the line isn't offered again), the
time zones after `time-zone=` (the IANA names of tzdata's `zone1970.tab`, and `UTC`), the admins
after `--admin`, `on` and `off` and `machine-api=` for `<product> mcp`, and `json` or `text`
after `-o`. `snea` and Tab gives `sneakers `. When Tab can't add anything because more than one
word fits, a second Tab lists them under the line and draws the prompt again. Only what the login
may run is offered: the other origin's commands never, and an admin who isn't an owner isn't
offered the owner-only commands (`network set`, `network confirm`, `setup recovery-key`), which
`help` doesn't list for them either; accessd still checks the role of every call. It's plain Tab
(0x09), so it works the same from OpenSSH, PuTTY and MobaXterm.
With no terminal, the code is one line of standard input, ended by Enter as LF, CRLF or a bare CR.

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
| `disk cleanup` | yes | yes | accessd; runs the disk cleanup now and prints what each step freed ([disk-layout.md](disk-layout.md#the-cleanup)) |
| `network show`, `network set key=value...`, `network confirm <token>` | yes | yes | accessd; `set` reverts in 120 s unless kept |
| `network allow-list reset` | yes | no | accessd; typed `reset` |
| `keys list` | yes | yes | accessd; keys are issued on :8443 |
| `admins list` | yes | yes | accessd; admins are managed on :8443 |
| `recovery-key add` | yes | no | accessd |
| `setup recovery-key` | no | yes | accessd; first boot only |
| `shell` | no | yes | accessd; root operators; see [The root shell](#the-root-shell) |
| `tls show`, `backup ...`, `restore ...`, `upgrade ...`, `resources ...` | yes | yes | Not available in this release |
| `logs export`, `support-bundle` | no | yes | Not available in this release |
| `updates`, `updates channel rc\|stable\|default`, `updates repo <owner>/<name>\|default` | yes | yes | accessd; see [The update channel](#the-update-channel) |
| `reboot`, `poweroff` | yes | yes | init, over `/run/sneakers/power.sock`; typed `reboot` or `poweroff`; always graceful |
| `<product> mcp [on\|off] [machine-api=on\|off]` (`sneakers mcp ...`) | no | yes | accessd; only while a product is installed; see [The MCP switch](#the-mcp-switch) |

Every command's help (`help <command>`) gives its purpose, its usage, its flags and keys, and an
example. The full reference, [cli.md](cli.md), is generated from the same command tree with
`go run ./build/tools/clidoc`; the shell's tests fail while the committed file is out of date, and
while any command lacks a description or an example.

A command offered only in the other origin is refused with `ACCESS_FORBIDDEN` and isn't listed by
`help` or completed. `-o json` prints a command's result, or its error as
`{"error": {"code", "number", "message"}}`. The commands of later specs answer `NOT_AVAILABLE`
("Not available in this release.") until their services are on the box. The accessd commands go to
`/run/sneakers/access.sock`, which knows the login by its uid ([access.md](access.md#accesssock));
`network set` takes `hostname`, `dns`, `search`, `ntp`, `allow-list` (comma-separated lists),
`time-zone` and `https-proxy` on top of the current settings. `help network set` lists every key
with an example, from the same table the parser reads, and so do `network set` alone and `network
set ?`; an unknown key answers `SHELL_PARSE` with the closest key ("did you mean time-zone?"). While accessd is down they answer
`NOT_AVAILABLE` ("the appliance services are unavailable"), and `status` shows the last status
accessd kept, with the time it was taken.

### Product commands

The commands above are the base appliance's, and they are the same on every box. An installed
product adds its own commands in a group named after it, listed by `help` under its own heading
("Sneakers commands (the installed product)") and completed like the others. The shell reads the
product's name from the current product slot's header (`/var/lib/sneakers/product/current/bundle.json`,
the `<name>-product` header name without `-product`) when the login starts. With no product
installed there is no group: nothing in `help` or completion names a product command, and `mcp` or
`sneakers mcp` is `SHELL_UNKNOWN`. Today the product group holds `mcp` and the product's exposed
values.

### The update channel

`updates` shows the update source, the channel the GitHub source follows (and whether it's this
build's default), the repository and the release last picked, and the rate limit's end while the
GitHub API's is used up. `updates channel rc` or `updates channel stable` sets the channel, and
`updates channel default` goes back to the build's default (rc on a pre-release build, stable
otherwise). `updates repo <owner>/<name>` points a lab build's built-in source at a test
repository and `updates repo default` clears it; a production build refuses it (`ACCESS_CONFIRM`).
These are the settings the mirror card on :8443 Updates shows ([upgrades.md](upgrades.md#the-github-source)):
accessd runs `UpgradeService.GetUpgrades` and `SetUpgradePolicy` as the login's admin, changing
only the channel or the repository and keeping the rest of the policy, so setting either is for
owners, and the change is audited as `upgrade.policy.set` like one made on :8443.

### The MCP switch

`<product> mcp` (`sneakers mcp`) shows the installed product's MCP switch and its machine API
switch; `<product> mcp on` and `<product> mcp off` set it. The machine API keeps its setting unless
the line names it: `<product> mcp off machine-api=off` turns both off, for a product that declares a
machine API switch. The help, its examples and Tab offer only the switches the installed product
declares: Sneakers declares `mcp` only, so `sneakers mcp` is offered without `machine-api=`, and
naming it anyway answers `NOT_AVAILABLE`. The switches are the ones the
product's `product.yaml` declares (`mcp` and `machine-api`), the same ones the MCP card on :8443
sets: accessd runs `McpService.GetMcp` and `McpService.SetMcp` as the login's admin, so the role
is the same (admin) and a change writes the same `mcp.set` audit entry, with the `ssh` surface.

```text
> sneakers mcp
MCP          off
machine API  on
> sneakers mcp on
MCP is on; the machine API is on.
```

A product that declares no MCP switch shows `not in this product`, and setting it answers
`NOT_AVAILABLE`. Anything but `on` or `off`, or a second word other than `machine-api=on|off`, is
`SHELL_PARSE`.

### Product values

A product's bundle may expose Secret values to owners and admins
([release.md](release.md#productyaml)), such as Sneakers' one-time setup token. Each is a command
in the product's group, `<product> <name>` (`sneakers setup-token`), over SSH only, offered only to
the roles the bundle lists for it (the shell reads the slot's `product.yaml` and the login's role).
It asks accessd, which runs `ProductService.GetExposedValue` as the login's admin, so the role is
checked again there, and prints the value with its label and link:

```text
Sneakers setup token:

    stp_...

Use it at https://box1.sneakers.example.org/admin/setup
It works once; after that it's removed.
```

A one-time value is consumed once the product's signal says so (for Sneakers, the gateway's
`/setup/state` answering `needsSetup: false`), and from then on the command only says it was used.
If the signal can't be read yet the value is still shown. There is no command that reads or lists any
other Secret. Each read is audited as `product.value.read` with the name and the outcome (`shown`
or `consumed`), never the value; a value that can't be read yet (k0s or the product isn't up) is
`PRODUCT_VALUE_UNAVAILABLE`.

## The root shell

A root operator ([access.md](access.md#roles-the-roster-and-step-up)) opens a root shell from the
closed shell:

1. `shell` asks accessd (`ElevationService.BeginRootShell`) for a challenge: 16 Crockford characters,
   shown with the time it is good until (the policy's minutes, 10 by default).
2. On :8443, signed in with a fresh step-up, the admin types the challenge
   (`RootShellService.IssueRootShellCode`) and gets an 8-character code: the first 40 bits of the root
   key's ed25519 signature over the challenge, the admin, the SSH source and the expiry. It is bound
   to that login and works once.
3. The admin types the code into the SSH session (`OpenRootShell`). Three wrong codes close the
   challenge, and they count toward the account's lockout. A right one gives a one-minute ticket.
4. The shell connects to `/run/sneakers/rootshell.sock` with the ticket and the terminal size; accessd
   starts `/usr/libexec/sneakers-elevated` as root with the connection as its terminal and relays
   data and resizes. The session ends after the policy's minutes, after 10 minutes idle, when the SSH
   client goes away, or when an owner ends it on the Sessions page.

The root shell is busybox ash. Its prompt, `[root@<host> until <HH:MM> UTC] <dir> # `, shows the
kernel host name ([network.md](network.md#dns-ntp-and-the-host-name): the configured name, else the
DHCP name, else the box's own `sneakers-<8 hex>`), when the session ends and the working directory.
It is plain text with only the prompt escapes `\h` and `\w`, nothing the shell expands or runs;
sneakers-elevated warns a minute before the end.

At its start the session says who it's for, that it's recorded and when it ends, and that `help`
lists the commands that help troubleshoot the box. `help` comes from the shell's start file
(`os/rootshell/rc.sh`, handed to ash through `ENV`): pods, logs, events, `k0s status`, the stacks
k0s applies, addresses and routes, DNS, name and port checks, disk, memory and the kernel log. It
also says why `helm list -A` is empty: the product's stacks are k0s manifests the appliance applies
from the installed bundle, not Helm releases, because the update slots and revert track the
manifests directly and Helm's release state would sit outside them.

With a product installed, `kubectl` and `helm` work in the root shell against its k0s with no setup:
`KUBECONFIG` is k0s's admin kubeconfig ([k0s.md](k0s.md#kubectl-and-helm-in-the-root-shell)).
Without one, the shell says so once at its start, and `kubectl`, `helm` and `k0s` each answer "No
product is installed yet" instead of a bare "not found".

`watch` (procps-ng, static) re-runs a command on an interval, such as `watch -n 2 kubectl get pods
-A`. The root carries the terminal descriptions it needs for xterm (OpenSSH, MobaXterm), PuTTY,
screen, tmux and the VT and Linux consoles; with another `TERM`, run it as `TERM=xterm watch ...`.

Every step is audited (`rootshell.begin`, `rootshell.code.issue`, `rootshell.open`, `rootshell.end`).
Removing an admin's key ends a root shell it opened.
