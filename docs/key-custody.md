# Key custody

One random 256-bit **state key** unlocks the LUKS2 state and backup volumes (AES-XTS, Argon2id
keyslot). First boot fixes where it's kept; it can't change without a reinstall and restore.

| Mode | Where the key is | When |
|---|---|---|
| TPM (the default when there is a TPM) | sealed in the TPM to PCR 7 and 11 with Secure Boot on, PCR 4 and 11 with it off; each copy is a `sneakers-tpm2` LUKS2 token | a TPM or vTPM is present and the admin didn't opt out |
| key file | the first 32 bytes of the `sneakers-keyfile` partition | no TPM (the lab ESXi host, a vCenter without a key provider, arm64 and the Pi), or the admin opted out |

The mode and the Secure Boot choice are recorded in a `sneakers-custody` token on the state
volume's LUKS2 header and read back on every boot; the ESP's choice file is deleted once the header
holds it. There's no boot passphrase and no key derived from the machine's identity.

On a later boot the key comes from the first TPM copy that unseals, or from the key file. When
neither works the state stays locked (`KEYCUSTODY_LOCKED`) and the console shows the "State locked"
screen; the escrow bundle is the way back.

## Protection

| Facts | Protection |
|---|---|
| no Secure Boot firmware | reduced (`no-secure-boot-firmware`) |
| Secure Boot off by choice, or not enforcing org-only keys | reduced (`secure-boot-off`) |
| key-file mode | reduced (`no-tpm`) |
| otherwise | full |
