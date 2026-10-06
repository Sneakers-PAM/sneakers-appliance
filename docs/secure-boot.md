# Secure Boot

Secure Boot is the admin's choice: on by default wherever the firmware supports it, and it can be
turned off on any host. With it on, PK, KEK and db hold only the org certificates ("custom mode");
the org certificate is never appended to a firmware's default keys.

## The choice

On firmware with Secure Boot, the `enrol` phase opens with one console screen:

- **Use Secure Boot with the org keys (recommended)** is selected; Enter keeps it.
- **Run without Secure Boot** needs the typed phrase `no secure boot`. Nothing is enrolled, and the
  box runs in reduced-protection mode; the org signature is still checked on every image and
  upgrade. On VMware the screen also asks you to remove `uefi.allowAuthBypass`.

The choice is kept on the ESP (`loader/sneakers/secure-boot`) until first boot fixes it in the
LUKS2 header; after that it changes only through the :8443 setting.

## Enrolment

Init enrols the org keys only when the firmware is in **Setup Mode** (no PK). It writes `db.auth`,
`KEK.auth` and then `PK.auth` (PK last, which ends Setup Mode) through efivarfs, reads each one
back, and skips a variable that already holds its new value, so a power cut part-way through is
finished on the next boot. Outside Setup Mode init writes nothing (`SB_NOT_SETUP_MODE`) and shows
how to clear the keys again, with the choice to run without Secure Boot.

| Platform | What the admin does |
|---|---|
| VMware (OVA or ISO) | Before the first boot: VM firmware setup, Boot Manager, Enter setup, Secure Boot Configuration, PK Options, Delete PK, untick "VMware Default PK", save. Boot once; init enrols. Then power off, turn Secure Boot on, remove `uefi.allowAuthBypass`, power on. |
| Proxmox VE, QEMU | Nothing: an EFI disk without pre-enrolled keys (`pre-enrolled-keys=0`) starts in Setup Mode; init enrols and restarts. |
| Bare metal | Clear the Secure Boot keys in the firmware setup (Setup Mode), then boot. |

If Secure Boot is turned on before the keys are enrolled, the firmware refuses the UKI (VMware
returns to its Boot Manager without an error). Turn Secure Boot off again, clear the keys, and boot
once.

## The mismatch rule

A box set to Secure Boot on whose firmware no longer enforces doesn't start the product. The
console shows: "Secure Boot is off, but this box is set to use it. Turn it back on in the firmware.
To run without it, turn it on, sign in to :8443 and turn Secure Boot off there." Pulling the
firmware setting alone can't move a box to reduced protection.
