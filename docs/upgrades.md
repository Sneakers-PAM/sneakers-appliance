# Image slots and boot counting

A release reaches the box as one signed and encrypted update package, the `.bin`, downloaded from
the GitHub Release or uploaded by hand ([release.md](release.md)). The box verifies the signature
and the channel before it decrypts anything, with the update key read from the UKI it booted; a lab package never installs on a production box.

A box holds at most two releases: the one it runs and one more (the next, or the previous).

- `Image.Stage` fetches a release, runs the whole verification chain against the keys compiled
  into the running init, and refuses anything not newer than the running release
  (`UPGRADE_DOWNGRADE`). Nothing is written before that passes. It then writes the root image into
  the slot the box isn't running from (setting that slot's PARTUUID from the root hash), adds a
  sealed copy of the state key for the new UKI (PCR 7 as it is now and the predicted PCR 11), and
  only then writes the ESP entry `EFI/Linux/sneakers-<version>+3-0.efi`. Entries other than the
  running release's are removed first.
- systemd-boot boots the newest entry; each attempt moves one try from left to done
  (`+2-1`, `+1-2`, ...). An entry with no tries left is bad and sorts last, so after three failed
  boots the box falls back to the previous release, and `Image.Status` reports the failed version.
- `Image.MarkGood`, after the health checks, renames the running entry to `sneakers-<version>.efi`
  and prunes sealed copies for UKIs no longer kept.
- `Image.Rollback` marks the running release bad (`+0-n`), so the next boot is the previous one.
  With no previous release it's `UPGRADE_NO_PREVIOUS`.
- With Secure Boot off (TPM mode), the new release's PCR 4 must be predicted from the firmware's
  event log; until that replay is in, staging is refused (`UPGRADE_UNPREDICTABLE`) rather than
  sealed to a guess.
