// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes

import apperr "github.com/Bugs5382/go-apperr"

// The first-boot and access codes (spec 2, Section 4.4). 3xxx: 30xx access,
// 33xx the root shell, 34xx network, 35xx setup,
// 36xx factory reset and power, 37xx the closed shell.
const (
	AccessKeyType          = 3001
	AccessKeyWeak          = 3002
	AccessKeyDuplicate     = 3003
	AccessName             = 3004
	AccessLastOwner        = 3006
	AccessLastRecoveryKey  = 3007
	AccessRecoveryKeyLimit = 3008
	AccessForbidden        = 3009
	AccessStepUpRequired   = 3010
	AccessStoreInvalid     = 3012
	AccessSession          = 3013
	AccessConfirm          = 3014
	AccessKeyRevoked       = 3015
	AccessPassword         = 3016
	AccessCredentials      = 3017
	AccessLocked           = 3018
	AccessThrottled        = 3019
	AccessNoAdmin          = 3020
	AccessPolicy           = 3021
	AccessQuorum           = 3022
	AccessKeyNoCertificate = 3023
	ElevExpired            = 3303
	ElevUsed               = 3304
	ElevMaintenance        = 3305
	ElevUnknown            = 3307
	RootChallenge          = 3308
	RootCode               = 3309
	NetInvalid             = 3401
	NetNoAddress           = 3402
	NetDHCPTimeout         = 3403
	NetGateway             = 3404
	NetDNS                 = 3405
	NetNTP                 = 3406
	NetReverted            = 3407
	SetupIncomplete        = 3501
	SetupCode              = 3502
	SetupDone              = 3503
	ResetUnavailable       = 3601
	ResetApproved          = 3602
	ResetCancelled         = 3603
	PowerForcedConfirm     = 3604
	ResetVerify            = 3605
	ResetQuorum            = 3606
	ResetFailed            = 3607
	PowerCaller            = 3608
	PowerBusy              = 3609
	PowerAudit             = 3610
	ShellParse             = 3701
	ShellUnknown           = 3702
	NotAvailable           = 3703
)

var accessEntries = []apperr.Entry{
	{Code: AccessKeyType, Symbol: "ACCESS_KEY_TYPE", Title: "access", Cause: "the key isn't an OpenSSH public key of an accepted type"},
	{Code: AccessKeyWeak, Symbol: "ACCESS_KEY_WEAK", Title: "access", Cause: "the key is DSA or RSA shorter than 3072 bits"},
	{Code: AccessKeyDuplicate, Symbol: "ACCESS_KEY_DUPLICATE", Title: "access", Cause: "the key is already a login key of an admin or a recovery key"},
	{Code: AccessName, Symbol: "ACCESS_NAME", Title: "access", Cause: "the admin name doesn't match the pattern, is reserved, or is taken"},
	{Code: AccessLastOwner, Symbol: "ACCESS_LAST_OWNER", Title: "access", Cause: "the change would leave no owner"},
	{Code: AccessLastRecoveryKey, Symbol: "ACCESS_LAST_RECOVERY_KEY", Title: "access", Cause: "the last recovery key can't be removed; add its replacement first"},
	{Code: AccessRecoveryKeyLimit, Symbol: "ACCESS_RECOVERY_KEY_LIMIT", Title: "access", Cause: "three recovery keys are already set"},
	{Code: AccessForbidden, Symbol: "ACCESS_FORBIDDEN", Title: "access", Cause: "the role or the origin doesn't allow it"},
	{Code: AccessStepUpRequired, Symbol: "ACCESS_STEPUP_REQUIRED", Title: "access", Cause: "a sign-in no older than 5 minutes is needed"},
	{Code: AccessStoreInvalid, Symbol: "ACCESS_STORE_INVALID", Title: "access", Cause: "the access store doesn't parse"},
	{Code: AccessSession, Symbol: "ACCESS_SESSION", Title: "access", Cause: "no session: signed out, idle for 15 minutes, past 8 hours, or its key or admin was removed"},
	{Code: AccessConfirm, Symbol: "ACCESS_CONFIRM", Title: "access", Cause: "the typed confirmation doesn't match"},
	{Code: AccessKeyRevoked, Symbol: "ACCESS_KEY_REVOKED", Title: "access", Cause: "the key was removed and is on the revocation list; an owner un-revokes it first"},
	{Code: AccessPassword, Symbol: "ACCESS_PASSWORD", Title: "access", Cause: "the password is shorter than 12 characters, on the breached-password list, or the admin's name"},
	{Code: AccessCredentials, Symbol: "ACCESS_CREDENTIALS", Title: "access", Cause: "the name, password or TOTP code is wrong, or the TOTP code was used already"},
	{Code: AccessLocked, Symbol: "ACCESS_LOCKED", Title: "access", Cause: "the account is locked after 3 failures in 15 minutes, for 15 minutes or until an owner unlocks it"},
	{Code: AccessThrottled, Symbol: "ACCESS_THROTTLED", Title: "access", Cause: "this source failed too often; it may try again after the time given"},
	{Code: AccessNoAdmin, Symbol: "ACCESS_NO_ADMIN", Title: "access", Cause: "sshd was asked to start while no admin has a password and a TOTP secret"},
	{Code: AccessPolicy, Symbol: "ACCESS_POLICY", Title: "access", Cause: "an access setting is out of its bounds"},
	{Code: AccessQuorum, Symbol: "ACCESS_QUORUM", Title: "access", Cause: "the root-operator roster would be empty, name someone who isn't an admin, or have a threshold out of range"},
	{Code: AccessKeyNoCertificate, Symbol: "ACCESS_KEY_NO_CERTIFICATE", Title: "access", Cause: "a box-issued SSH key was sent without its certificate; sshd takes only the certificate (load <key>-cert.pub, or use the .ppk)"},
	{Code: ElevExpired, Symbol: "ELEV_EXPIRED", Title: "elevation", Cause: "the request or certificate expired"},
	{Code: ElevUsed, Symbol: "ELEV_USED", Title: "elevation", Cause: "the certificate was already used"},
	{Code: ElevMaintenance, Symbol: "ELEV_MAINTENANCE", Title: "elevation", Cause: "an upgrade is in progress"},
	{Code: ElevUnknown, Symbol: "ELEV_UNKNOWN", Title: "elevation", Cause: "no elevation request or certificate has that id"},
	{Code: RootChallenge, Symbol: "ROOT_CHALLENGE", Title: "root shell", Cause: "the root-shell challenge is unknown, expired, closed or someone else's"},
	{Code: RootCode, Symbol: "ROOT_CODE", Title: "root shell", Cause: "the code doesn't match the challenge"},
	{Code: NetInvalid, Symbol: "NET_INVALID", Title: "network", Cause: "a setting fails validation (the error names the field)"},
	{Code: NetNoAddress, Symbol: "NET_NO_ADDRESS", Title: "network", Cause: "the management interface has no usable address"},
	{Code: NetDHCPTimeout, Symbol: "NET_DHCP_TIMEOUT", Title: "network", Cause: "no DHCP server answered in time"},
	{Code: NetGateway, Symbol: "NET_GATEWAY", Title: "network", Cause: "the gateway didn't answer ARP or neighbour discovery"},
	{Code: NetDNS, Symbol: "NET_DNS", Title: "network", Cause: "a DNS server didn't answer"},
	{Code: NetNTP, Symbol: "NET_NTP", Title: "network", Cause: "no NTP server gave a usable time"},
	{Code: NetReverted, Symbol: "NET_REVERTED", Title: "network", Cause: "a change wasn't confirmed in 120 seconds and was undone"},
	{Code: SetupIncomplete, Symbol: "SETUP_INCOMPLETE", Title: "setup", Cause: "a setup step is still open (the error names it)"},
	{Code: SetupCode, Symbol: "SETUP_CODE", Title: "setup", Cause: "a wrong, used or expired one-time code (setup, invitation or Recover access)"},
	{Code: SetupDone, Symbol: "SETUP_DONE", Title: "setup", Cause: "setup is done: a setup-only call, or a call with a setup code's session"},
	{Code: ResetUnavailable, Symbol: "RESET_UNAVAILABLE", Title: "reset", Cause: "no factory reset: a single admin, a roster that can't reach its threshold, or one already in progress"},
	{Code: ResetApproved, Symbol: "RESET_APPROVED", Title: "reset", Cause: "this admin's approval is already counted, or they aren't on the roster"},
	{Code: ResetCancelled, Symbol: "RESET_CANCELLED", Title: "reset", Cause: "the factory reset was cancelled, expired or never started"},
	{Code: PowerForcedConfirm, Symbol: "POWER_FORCED_CONFIRM", Title: "power", Cause: "a forced reboot or shutdown needs its second, explicit confirmation"},
	{Code: ResetVerify, Symbol: "RESET_VERIFY", Title: "reset", Cause: "the factory reset's check failed (a partition or a LUKS, filesystem or GPT signature is still there); the box doesn't reboot"},
	{Code: ResetQuorum, Symbol: "RESET_QUORUM", Title: "reset", Cause: "init refused the factory reset: not armed, approvals that aren't a quorum of the roster, the delay not over, or expired"},
	{Code: ResetFailed, Symbol: "RESET_FAILED", Title: "reset", Cause: "a factory reset step failed (the error names it); the reset carries on at the next boot"},
	{Code: PowerCaller, Symbol: "POWER_CALLER", Title: "power", Cause: "init takes power and reset requests only from osadmin and the closed shell"},
	{Code: PowerBusy, Symbol: "POWER_BUSY", Title: "power", Cause: "a reboot, shutdown or factory reset is already under way"},
	{Code: PowerAudit, Symbol: "POWER_AUDIT", Title: "power", Cause: "the OS audit log can't be written, so init doesn't act on the request"},
	{Code: ShellParse, Symbol: "SHELL_PARSE", Title: "shell", Cause: "the command line doesn't parse: an open quote, a control character, or longer than 64 KiB"},
	{Code: ShellUnknown, Symbol: "SHELL_UNKNOWN", Title: "shell", Cause: "there is no such command; help lists them"},
	{Code: NotAvailable, Symbol: "NOT_AVAILABLE", Title: "shell", Cause: "not available in this release, or the appliance services aren't answering"},
}

func init() { Entries = append(Entries, accessEntries...) }
