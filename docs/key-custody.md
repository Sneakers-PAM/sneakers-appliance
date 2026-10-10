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

## At boot

Init ([init.md](init.md)) runs the custody before any service starts:

- **First boot, the protection step.** The console shows the Secure Boot facts, then the custody:
  with a TPM, "Use the TPM (recommended)" is the default (Enter), and only the typed `key file`
  picks the key file, after the reduced-protection text; without a TPM the key file is the only
  custody and Enter goes on. Init then initializes the custody: it adds the key-file (key-file mode
  only), state and backup partitions to the GPT after the installed ones and tells the kernel
  about each (`BLKPG`, while the ESP stays mounted), formats state and backup as LUKS2 with the one
  new key, makes their ext4 filesystems with the image's static `mkfs.ext4`, and records the mode
  and the Secure Boot choice in the header. The choice is `on` only when the firmware enforces with
  the org keys and the admin didn't choose to run without Secure Boot. A first boot cut short
  before the header was written makes its partitions again.
- **Every boot.** Init reads the header, which fixes the Secure Boot choice for the phase decision,
  unlocks state and backup and mounts them, state at `/var/lib` and backup at
  `/var/lib/sneakers/backup` (nosuid, nodev), then finishes a Secure Boot transition if the
  firmware shows it took effect. A volume that doesn't unlock stops the boot: the console shows
  "State locked" with the reason, and nothing starts, so no service ever runs against an empty or
  read-only `/var/lib/sneakers`.
- The keyslot uses Argon2id at a low cost (64 MiB, one lane): the key is 256 random bits, not a
  passphrase, so a higher cost would only slow every boot.
- The console then prints the protection line ([Protection](#protection)), and the KeyCustody
  service is served on `init.sock`.

## The KeyCustody service

Init serves `KeyCustodyService` on `init.sock` (root peers only, checked with `SO_PEERCRED`):

| RPC | What it does |
|---|---|
| `Mode` | `tpm` or `keyfile`, as the header records it |
| `Protection` | `full` or `reduced` with the reason (`no-secure-boot-firmware`, `secure-boot-off`, `no-tpm`); the :8443 Status page shows it |
| `Seal`, `Unseal` | the sealed items below; an item never sealed is `NotFound` (`KEYCUSTODY_NOT_FOUND`) |
| `Escrow` | the escrow bundle for one to three recovery keys |

`Initialize` and `SetSecureBoot` answer `Unimplemented`: init fixes the custody at its own
protection step, and the :8443 Secure Boot setting comes later. accessd seals the SSH user CA
through it ([ssh-and-elevation.md](ssh-and-elevation.md)).

## Protection

| Facts | Protection |
|---|---|
| no Secure Boot firmware | reduced (`no-secure-boot-firmware`) |
| Secure Boot off by choice, or not enforcing org-only keys | reduced (`secure-boot-off`) |
| key-file mode | reduced (`no-tpm`) |
| otherwise | full |

## Sealed items and the escrow

`Seal(name, secret)` keeps a small secret (the vault root key first) under the state key: AES-256-GCM
with a key derived from the state key (HKDF-SHA256), the item's name as associated data, one file
per item under `/var/lib/sneakers/sealed/` on the state volume, written to a temporary file that's
synced, renamed into place and the directory synced, so a power cut leaves the old item or the new
one, never an empty file. `Unseal(name)` returns it.

`Escrow(recipients)` returns the escrow bundle: the state key and every sealed item, encrypted with
age to one to three SSH recovery keys (`ssh-ed25519` or `ssh-rsa`;
security-key types are refused, because a restore mustn't need the hardware the key was made on).
Each recovery key opens it on its own, with the stock `age -d -i <private key>`. A restore onto new
hardware uses it; losing the TPM without the escrow loses the data.

## Product keys

A product's `product.yaml` names the keys its data can't be opened without, under `escrow`
([release.md](release.md#productyaml)); the Sneakers bundle names the vault's root key
(`VAULT_ROOT_KEK`) and the identity service's TOTP key (`TOTP_ENC_KEY`). The box reads each from the
product's Secret, as the appliance's own service account (whose Role names those Secrets), and seals
it as the item `product-<product>-<name>`, so the escrow carries it with the state key. This runs
each time an owner downloads the escrow (`SetupService.DownloadEscrow`): a key that is new or has
changed is sealed again and a new escrow file is written to the current recovery keys before the
download, so **download the escrow after the product is installed**, and again after an import or
anything that changes the keys. A key the product hasn't made yet is sealed next time.

Restoring the product onto a replacement box: decrypt the escrow with one recovery key
(`age -d -i <private key> escrow-*.age`). It is JSON: `items` maps each sealed item's name to its
value (base64). Bring it in at the new box's first boot with `KeyCustody.ImportEscrow` (below),
**before the product is installed**. When the product's first apply makes its box secrets
([release.md](release.md#productyaml)), a key the bundle names under `escrow` that the box hasn't
made yet is read from the sealed item `product-<product>-<name>` instead of made anew, so the new
box's `VAULT_ROOT_KEK` and `TOTP_ENC_KEY` are the old box's and the restored data opens. Keys
with nothing escrowed are made as usual. If the sealed items can't be read, the apply stops rather
than make a key that would leave the data unreadable.

Don't edit the product's Secrets with `kubectl`: the box writes `sneakers-box` from its own store
(`box-secrets.json`) at every product apply and revert, so an edit is undone. A box that has
already made its own product keys keeps them; restore onto a box whose product isn't installed
yet. Without the vault's root key no stored secret opens; without the TOTP key every second factor
has to be enrolled again.

## Importing an escrow on new hardware

A restore onto new hardware brings the old box's sealed items back with
`KeyCustody.ImportEscrow`. It takes the escrow already decrypted with one recovery key and seals
each item again under the new box's own state key; the old box's state key is never used. It runs
only in `firstboot` and only while nothing is sealed on the new box yet; anything else is refused
with `KEYCUSTODY_PHASE`. An escrow that doesn't parse, has an unknown version or names an invalid
item is refused with `KEYCUSTODY_INVALID` and nothing is sealed.

## Turning Secure Boot off and on later

- **Off** (`KeyCustody.SetSecureBoot(off)`): in TPM mode a copy sealed to PCR 4 and 11 is added
  first, then `off` is recorded. On the next boot with Secure Boot off in the firmware, the PCR 7
  and 11 copies are dropped.
- **On later**: `on` is recorded with enrolment pending, and the PCR 4 and 11 copy is kept, so the
  boots before the org keys enforce still unlock. The next boot enters `enrol`. Once the firmware
  enforces with only the org keys, init seals a copy to the new PCR 7 and 11, checks it unseals,
  and only then drops the PCR 4 and 11 copy; protection becomes full. Key-file mode records the
  choice only.
- PCR 4 for a staged release (with Secure Boot off) is predicted by replaying the firmware's event
  log (`tpm.ReplayPCR4`) with the new loader's, UKI's and kernel's Authenticode digests in place of
  the running ones; a log that can't be read or has no EFI application events is refused rather
  than guessed at.
