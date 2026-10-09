# The appliance admin API

`sneakers-osadmin` serves the :8443 appliance admin: the static admin pages and a Connect API
(gRPC, gRPC-Web and JSON over HTTP) generated from `proto/sneakers/appliance/osadmin/v1`. It runs
unprivileged and forwards the API to `sneakers-accessd`, which checks the session, role and step-up
of every call and carries it out ([access.md](access.md#accessd)). Sign-in, sessions, roles and
step-up are described in [access.md](access.md#the-8443-sign-in). While accessd is down every call
answers Connect `unavailable` ("the appliance services are unavailable").

## Calling it

- **Transport.** HTTPS on port 8443 of each management address only, with the box's own certificate
  (ECDSA P-256, self-signed, names = the host name and the management addresses) until an owner
  assigns one from the certificate store. Check its SHA-256 fingerprint against the console on the
  first visit.
- **Session.** The `__Host-osadmin-session` cookie, set by `SignInService.PollSignIn` once the code
  is approved over SSH.
- **CSRF.** Every call that changes something sends the session's `csrf_token` in the
  `X-CSRF-Token` header. Reads (`NO_SIDE_EFFECTS` in the proto, also callable with Connect's GET)
  don't need it.
- **Errors.** Coded errors start with their symbol ([errors.md](errors.md)):
  `ACCESS_SESSION` is `unauthenticated`; `ACCESS_FORBIDDEN` and `ACCESS_STEPUP_REQUIRED` are
  `permission_denied`; a refused key, name, confirmation or network setting is `invalid_argument`;
  the other refusals are `failed_precondition`. A service whose backend isn't on the box yet answers
  `unimplemented` with "Not available in this release", and its page says so.
- **Rules.** Each method carries a `(sneakers.appliance.osadmin.v1.rule)` option: the least role,
  whether it needs a step-up (or a fresh code on every call), and the OS audit action written for
  every call, allowed or refused.
  osadmin enforces the rule from the descriptor; a method without one is refused.

## Other endpoints

| Endpoint | What it does |
|---|---|
| `GET /export/audit-log` | the whole OS audit log as written (JSON lines, oldest first), so the chain verifies off the box; needs a session, audited as `audit.export` |
| `POST /upload` | an update `.bin` as the request body (at most 8 GiB), with the session cookie and `X-CSRF-Token`, and the file's name in `X-File-Name` (optional, URL-encoded; shown on the held upload only); answers `{"uploadId": "..."}` for `UpgradeService.StageUpdate`; audited as `upgrade.upload`. Nothing is verified or unpacked until it's staged. One file at a time: while another is coming in or held, or a stage runs, it answers `409` with `UPGRADE_BUSY`. A transfer the browser aborts leaves no file |
| `GET /` and anything else | the admin pages, with the page routes falling back to `index.html`. Until setup is done (`StatusService.GetPhase` answers `firstboot`), every page path but `/setup`, `/` included, answers `302` to `/setup`; the files the pages load are served in both phases |

Every response carries `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri
'none'; form-action 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

## Methods

Role `public` needs no session; `admin` is any signed-in admin; `owner` only an owner; `code
session` is the session a redeemed one-time code gives (the setup code, an invitation or a Recover
access code). Step-up means a sign-in or a fresh TOTP code (`SignInService.StepUp`) from the last 5
minutes. `every call` means the request carries its own `totp_code`, a fresh code checked on every
call whatever the step-up window says; an empty code is `ACCESS_CONFIRM`, and a wrong or reused one
is `ACCESS_CREDENTIALS` and counts toward the sign-in lockout.

Setup only: `SetupService.AcknowledgeStep`, `SetupService.AcknowledgeSingleAdmin` and
`SetupService.Finish` are refused with `SETUP_DONE` once setup is done (the rule's `setup_only`),
and so is every call made with a setup code's session, so a stepper left open can't go on. The
refusal is audited under the method's action. The recovery keys and the escrow stay an owner's
after setup, and invitations and Recover access codes still use the code pages.

### Available in this release

| Method | Role | Step-up | Audit action |
|---|---|---|---|
| `SignInService.SignIn` | public | no | `signin.password` |
| `SignInService.StepUp` | admin | no | `signin.step-up` |
| `SignInService.BeginSignIn` | public | no | |
| `SignInService.PollSignIn` | public | no | |
| `SignInService.GetSession` | admin | no | |
| `SignInService.SignOut` | admin | no | `signin.signout` |
| `StatusService.GetStatus` | admin | no | |
| `StatusService.SetSecureBoot` | owner | yes | `status.secure-boot.set` |
| `StatusService.GetPhase` | public | no | |

`GetPhase` answers `phase` (`firstboot` until setup's Finish, then `normal`) and, for the product
edge's box-state page ([edge-fallback.md](edge-fallback.md)), `state`: `updating` while an update
applies or reverts (through the reboot it ends in), else `rebooting` or `shutting-down` once init
has announced one, else `running` when setup is done and the product's service (k0s) runs, else
`starting`. `maintenance` is reserved for platformd's maintenance mode. `product_running` and
`product_installed` say whether k0s runs and whether a product bundle is installed.
`upgrade_progress` is an update's steps while one is in progress and for 15 minutes after it ends,
for the restart page before anyone signs in again: each step's id, label and state only, with no
version, detail or code ([upgrades.md](upgrades.md#the-steps-of-an-update)). It says nothing else
about the box.
| `SetupService.GetSetup` | admin or code session | no | |
| `SetupService.RedeemCode` | public | no | `setup.code.redeem` |
| `SetupService.CheckPassword` | admin or code session | no | |
| `SetupService.BeginCredentials` | code session | no | `setup.credentials.begin` |
| `SetupService.CompleteCredentials` | code session | no | `setup.credentials.complete` |
| `SetupService.AcknowledgeStep` | owner | no | `setup.step.acknowledge` |
| `SetupService.AddRecoveryKey` | owner | yes | `setup.recovery-key.add` |
| `SetupService.GenerateRecoveryKey` | owner | yes | `setup.recovery-key.generate` |
| `SetupService.RemoveRecoveryKey` | owner | yes | `setup.recovery-key.remove` |
| `SetupService.DownloadEscrow` | owner | no | `setup.escrow.download` |
| `SetupService.AcknowledgeSingleAdmin` | owner | no | `setup.single-admin.acknowledge` |
| `SetupService.Finish` | owner | no | `setup.finish` |
| `AccessService.ListAdmins` | admin | no | |
| `AccessService.AddAdmin` | owner | yes | `access.admin.add` |
| `AccessService.RemoveAdmin` | owner | yes | `access.admin.remove` |
| `AccessService.SetRole` | owner | yes | `access.admin.role` |
| `AccessService.AddKey` | admin | yes | `access.key.add` |
| `AccessService.RemoveKey` | admin | yes | `access.key.remove` |
| `AccessService.UnrevokeKey` | owner | yes | `access.key.unrevoke` |
| `AccessService.SetElevationPolicy` | owner | yes | `access.elevation-policy.set` |
| `AccessService.SetQuorum` | owner | yes | `access.quorum.set` |
| `AccessService.IssueSshKey` | admin | every call | `access.ssh-key.issue` |
| `AccessService.ChangePassword` | admin | yes | `access.password.change` |
| `AccessService.BeginTotpReplacement` | admin | yes | `access.totp.begin` |
| `AccessService.CompleteTotpReplacement` | admin | yes | `access.totp.replace` |
| `AccessService.ReinviteAdmin` | owner | yes | `access.admin.reinvite` |
| `AccessService.UnlockAdmin` | owner | yes | `access.admin.unlock` |
| `AccessService.SetAccessPolicy` | owner | yes | `access.policy.set` |
| `NetworkService.GetNetwork` | admin | no | |
| `NetworkService.SetNetwork` | owner | yes | `network.set` |
| `NetworkService.ConfirmNetwork` | owner | no | `network.confirm` |
| `NetworkService.RunChecks` | admin | no | |
| `AuditService.ListEvents` | admin | no | |
| `PowerService.GetPower` | admin | no | |
| `PowerService.Reboot` | admin | yes | `power.reboot` |
| `PowerService.Shutdown` | admin | yes | `power.shutdown` |
| `PowerService.StartFactoryReset` | owner | yes | `power.factory-reset.start` |
| `PowerService.ApproveFactoryReset` | admin | yes | `power.factory-reset.approve` |
| `PowerService.CancelFactoryReset` | admin | no | `power.factory-reset.cancel` |
| `PowerService.ListSessions` | admin | no | |
| `PowerService.EndSession` | owner | no | `session.end` |
| `UpgradeService.GetUpgrades` | admin | no | |
| `UpgradeService.FetchUpdate` | admin | no | `upgrade.fetch` |
| `UpgradeService.StageUpdate` | owner | no | `upgrade.stage` |
| `UpgradeService.ApplyUpdate` | owner | every call | `upgrade.apply` |
| `UpgradeService.RevertUpdate` | owner | every call | `upgrade.revert` |
| `UpgradeService.DiscardUpdate` | owner | no | `upgrade.discard` |
| `UpgradeService.ListProductVersions` | admin | no | |
| `UpgradeService.SetUpgradePolicy` | owner | no | `upgrade.policy.set` |
| `ElevationService.ListElevations` | admin | no | |
| `ElevationService.ApproveElevation` | owner | yes | `elevation.approve` |
| `ElevationService.DenyElevation` | owner | no | `elevation.deny` |
| `ElevationService.TerminateElevation` | owner | no | `elevation.terminate` |
| `ElevationService.GetElevationRecording` | owner | no | `elevation.recording.view` |
| `TlsService.GetCertificateStore` | admin | no | |
| `TlsService.GenerateCsr` | owner | no | `tls.csr.generate` |
| `TlsService.CompleteCsr` | owner | no | `tls.csr.complete` |
| `TlsService.DiscardCsr` | owner | no | `tls.csr.discard` |
| `TlsService.ImportCertificate` | owner | no | `tls.certificate.import` |
| `TlsService.DeleteCertificate` | owner | no | `tls.certificate.delete` |
| `TlsService.AssignCertificate` | owner | yes | `tls.endpoint.assign` |
| `TlsService.RevertToSelfSigned` | owner | yes | `tls.endpoint.revert` |
| `TlsService.SetAcme` | owner | no | `tls.acme.set` |
| `TlsService.RenewNow` | owner | no | `tls.acme.renew` |
| `TlsService.SetUpdateTrust` | owner | no | `tls.update-trust.set` |
| `TlsService.ClearUpdateTrust` | owner | no | `tls.update-trust.clear` |
| `RootShellService.IssueRootShellCode` | admin | no | `rootshell.code.issue` |

Sessions: `ListSessions` lists every live session on the box, oldest first, each an
`ActiveSession` with its `id`, `kind` (`SESSION_KIND_BROWSER` for a signed-in :8443 browser,
`SESSION_KIND_SSH` for an admin's SSH login to the closed shell, `SESSION_KIND_ELEVATED` for an
active elevated shell), `admin`, `source_address` and start time (`signed_in`). The SSH sessions
are read from the process table each time (every `sneakers-shell` process sshd started), and the
elevated ones from the elevation service once it has swept the sessions whose process is gone, so
the list is what is running. `GetPower` returns the same list, for the warning before a reboot or
shutdown. `EndSession` takes an `id` from the list: a browser is signed out at once, an SSH login
is hung up (the shell gets SIGHUP, the sshd process for its connection SIGTERM, and the shell
SIGKILL if it is still there 5 seconds later), and an elevated shell is ended as
`TerminateElevation` ends it. The audit entry's detail records `kind`, `admin` and `source`. A
browser's `id` is derived from its session and is never its cookie. An `id` that names no live
session answers `NotFound`.

Certificates: `TlsService` runs the box's certificate store ([certificates.md](certificates.md)).
`GetCertificateStore` lists the store's certificates (`StoredCertificate`: subject, issuer, SANs,
not-before and not-after, SHA-256 fingerprint, key type, chain, source and the endpoints that use
it), the pending CSRs, the endpoints (`admin` for :8443 and `product` for 443, which answers
"Available when the product is installed") and the ACME state. `ImportCertificate` takes a PFX
(PKCS#12) with its password, the main path, or PEM; the password is never stored and the PFX is
never kept. `GenerateCsr` makes the key on the box (RSA 4096 by default; RSA 3072, ECDSA P-256 or
P-384), seals it, and returns the CSR for one extra name plus the host name and the management
addresses; a wildcard or a second extra name is refused (`TLS_INVALID`). `CompleteCsr` takes the
signed certificate and chain for a pending CSR. `ImportCertificate` and `CompleteCsr` check the key, the usage, the chain to a root (one in the
chain, or `root_pem`), the SANs (a wildcard covers one label) and the validity, and refuse RSA below 3072 bits; a refusal's error names the first failure and
carries every check as a `ValidationReport` detail, and nothing is stored. `AssignCertificate` makes
:8443 serve a store certificate without a restart, checks it with a handshake to each management
address, and answers `TLS_NOT_SERVED` with the previous certificate back in place if it isn't served
within 15 seconds. `RevertToSelfSigned` puts the box's own certificate back. `DeleteCertificate` is
refused while an endpoint uses the certificate. `SetAcme` and `RenewNow` answer
`TLS_ACME_UNAVAILABLE` until the product bundle brings cert-manager. The earlier `GetTls`,
`CreateCsr`, `UploadCertificate` and `SetAdminCertificate` stay Not available; the store methods
replace them. Every change's audit entry records the method, the store id, the fingerprint, the SANs
and the expiry.

Root shells: `ApproveElevation` and `DenyElevation` are gone (deprecated in the proto, answering
`Unimplemented`); a root shell needs no approval, only the challenge and the code
`RootShellService.IssueRootShellCode` gives for it. `TerminateElevation` ends an active root shell.
`GetElevationRecording` returns the asciicast recording with `verified` set when every chunk hash in
the OS audit log matches. See [ssh-and-elevation.md](ssh-and-elevation.md#the-root-shell).

### Not available in this release

The pages for these services show "Not available in this release" until their backends ship.

| Method | Role | Step-up | Audit action |
|---|---|---|---|
| `TlsService.GetTls` | admin | no | |
| `TlsService.CreateCsr` | admin | no | `tls.csr.create` |
| `TlsService.UploadCertificate` | admin | no | `tls.certificate.upload` |
| `TlsService.SetAdminCertificate` | owner | yes | `tls.admin-certificate.set` |
| `McpService.GetMcp` | admin | no | |
| `McpService.SetMcp` | admin | yes | `mcp.set` |
| `BackupService.GetBackups` | admin | no | |
| `BackupService.SetBackupPolicy` | admin | no | `backup.policy.set` |
| `BackupService.RunBackup` | admin | no | `backup.run` |
| `BackupService.Restore` | owner | yes | `backup.restore` |
| `ModulesService.ListModules` | admin | no | |
| `ModulesService.AddModule` | owner | yes | `modules.add` |

## The local socket

accessd serves `LocalService` on `/run/sneakers/access.sock` to the closed shell and the console
(root and the admin uids, read with `SO_PEERCRED`; `sneakers-osadmin` never forwards it). Root may
act as any admin; an admin uid only as itself. The rest of that socket's API is in
[access.md](access.md#accesssock).

| Method | What it does |
|---|---|
| `LocalService.DescribeSignIn` | the browser's address, user agent and expiry for a code, for the approval prompt |
| `LocalService.ApproveSignIn` | binds the waiting browser to the admin and the key fingerprint that authenticated the SSH session; audited as `signin.approve` with the browser's address and user agent |
| `LocalService.LocalCancelFactoryReset` | stops a factory reset or its countdown (the console, or a closed-shell login as itself); audited as `power.factory-reset.cancel` |
