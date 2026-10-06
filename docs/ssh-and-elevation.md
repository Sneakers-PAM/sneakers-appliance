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
