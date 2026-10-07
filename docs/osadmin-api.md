# The appliance admin API

`sneakers-osadmin` serves the :8443 appliance admin: the static admin pages and a Connect API
(gRPC, gRPC-Web and JSON over HTTP) generated from `proto/sneakers/appliance/osadmin/v1`. It runs
unprivileged and forwards the API to `sneakers-accessd`, which checks the session, role and step-up
of every call and carries it out ([access.md](access.md#accessd)). Sign-in, sessions, roles and
step-up are described in [access.md](access.md#the-8443-sign-in). While accessd is down every call
answers Connect `unavailable` ("the appliance services are unavailable").

## Calling it

- **Transport.** HTTPS on port 8443 of each management address only, with the box's own certificate
  (ECDSA P-256, self-signed, names = the host name and the management addresses). Check its
  SHA-256 fingerprint against the console on the first visit.
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
  whether it needs a step-up, and the OS audit action written for every call, allowed or refused.
  osadmin enforces the rule from the descriptor; a method without one is refused.

## Other endpoints

| Endpoint | What it does |
|---|---|
| `GET /export/audit-log` | the whole OS audit log as written (JSON lines, oldest first), so the chain verifies off the box; needs a session, audited as `audit.export` |
| `POST /upload` | an update `.bin` as the request body (at most 8 GiB), with the session cookie and `X-CSRF-Token`; answers `{"uploadId": "..."}` for `UpgradeService.StageUpdate`; audited as `upgrade.upload`. Nothing is verified or unpacked until it's staged |
| `GET /` and anything else | the admin pages, with the page routes falling back to `index.html` |

Every response carries `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri
'none'; form-action 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

## Methods

Role `public` needs no session; `admin` is any signed-in admin; `owner` only an owner; `code
session` is the session a redeemed one-time code gives (the setup code, an invitation or a Recover
access code). Step-up means a sign-in or a fresh TOTP code (`SignInService.StepUp`) from the last 5
minutes.

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
| `SetupService.GetSetup` | admin or code session | no | |
| `SetupService.RedeemCode` | public | no | `setup.code.redeem` |
| `SetupService.CheckPassword` | admin or code session | no | |
| `SetupService.BeginCredentials` | code session | no | `setup.credentials.begin` |
| `SetupService.CompleteCredentials` | code session | no | `setup.credentials.complete` |
| `SetupService.AcknowledgeStep` | owner | no | `setup.step.acknowledge` |
| `SetupService.AddRecoveryKey` | owner | yes | `setup.recovery-key.add` |
| `SetupService.RemoveRecoveryKey` | owner | yes | `setup.recovery-key.remove` |
| `SetupService.DownloadEscrow` | owner | no | `setup.escrow.download` |
| `SetupService.AcknowledgeSingleAdmin` | owner | no | `setup.single-admin.acknowledge` |
| `SetupService.Finish` | owner | yes | `setup.finish` |
| `AccessService.ListAdmins` | admin | no | |
| `AccessService.AddAdmin` | owner | yes | `access.admin.add` |
| `AccessService.RemoveAdmin` | owner | yes | `access.admin.remove` |
| `AccessService.SetRole` | owner | yes | `access.admin.role` |
| `AccessService.AddKey` | admin | yes | `access.key.add` |
| `AccessService.RemoveKey` | admin | yes | `access.key.remove` |
| `AccessService.UnrevokeKey` | owner | yes | `access.key.unrevoke` |
| `AccessService.SetElevationPolicy` | owner | yes | `access.elevation-policy.set` |
| `AccessService.SetQuorum` | owner | yes | `access.quorum.set` |
| `AccessService.IssueSshKey` | admin | yes | `access.ssh-key.issue` |
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
| `PowerService.EndSession` | owner | yes | `session.end` |
| `UpgradeService.GetUpgrades` | admin | no | |
| `UpgradeService.FetchUpdate` | admin | no | `upgrade.fetch` |
| `UpgradeService.StageUpdate` | owner | yes | `upgrade.stage` |
| `UpgradeService.ApplyUpdate` | owner | yes | `upgrade.apply` |
| `UpgradeService.RevertUpdate` | owner | yes | `upgrade.revert` |
| `UpgradeService.ListProductVersions` | admin | no | |
| `UpgradeService.SetUpgradePolicy` | owner | yes | `upgrade.policy.set` |
| `ElevationService.ListElevations` | admin | no | |
| `ElevationService.ApproveElevation` | owner | yes | `elevation.approve` |
| `ElevationService.DenyElevation` | owner | no | `elevation.deny` |
| `ElevationService.TerminateElevation` | owner | no | `elevation.terminate` |
| `ElevationService.GetElevationRecording` | owner | no | `elevation.recording.view` |
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

Shell elevation: `ApproveElevation` signs the requester's certificate and may shorten the request
(`minutes`, never longer). With two or more owners nobody approves their own request
(`ELEV_SELF_APPROVAL`); the only owner may, and the request is flagged `self_approved` (and on
Status, `WARNING_KIND_SELF_APPROVED_ELEVATION`, while it is approved or active).
`TerminateElevation` ends an active session or revokes an approved certificate nobody has used.
`GetElevationRecording` returns the asciicast recording with `verified` set when every chunk hash
in the OS audit log matches. See [ssh-and-elevation.md](ssh-and-elevation.md#one-time-elevation).

### Not available in this release

The pages for these services show "Not available in this release" until their backends ship.

| Method | Role | Step-up | Audit action |
|---|---|---|---|
| `TlsService.GetTls` | admin | no | |
| `TlsService.CreateCsr` | admin | no | `tls.csr.create` |
| `TlsService.UploadCertificate` | admin | yes | `tls.certificate.upload` |
| `TlsService.SetAdminCertificate` | owner | yes | `tls.admin-certificate.set` |
| `McpService.GetMcp` | admin | no | |
| `McpService.SetMcp` | admin | yes | `mcp.set` |
| `BackupService.GetBackups` | admin | no | |
| `BackupService.SetBackupPolicy` | admin | yes | `backup.policy.set` |
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
