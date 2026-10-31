# Run the Sneakers appliance on Proxmox VE

This guide imports `sneakers-appliance-<version>-amd64.qcow2` into Proxmox VE as a new VM and boots it.
On the first boot the appliance enrols its own Secure Boot keys and restarts; on the second it keeps
its disk keys in the VM's TPM and opens its setup page. The guide uses only the Proxmox VE web UI
and the `qm` command on the Proxmox host.

**Untested on Proxmox VE so far.** CI boots this image in QEMU with exactly the VM shape below, but
it hasn't been imported into a real Proxmox VE host yet. If a step here doesn't match what you see,
open an issue at <https://github.com/Sneakers-PAM/sneakers-appliance/issues>.

## Before you start

- A Proxmox VE 8 host, and a root shell on it (the web UI's **Shell** for the node, or SSH).
- A storage that holds VM disks, such as `local-lvm`, with 64 GiB free (the image is thin,
  so less is used at first), and a bridge for the VM's network, such as `vmbr0`.
- 4 CPU cores and 16 GiB of memory for the VM.
- A free VM ID, such as `120` (`pvesh get /cluster/nextid` prints one).
- The release you're installing, such as `0.1.0-rc.4` (the tag without its `v`), from
  <https://github.com/Sneakers-PAM/sneakers-appliance/releases>.

## 1. Set the names this guide uses

In the root shell on the Proxmox host, set the VM ID, the storage, the bridge and where the image
is. Change the values to yours:

```sh
VMID=120
STORAGE=local-lvm
BRIDGE=vmbr0
VERSION=0.1.0-rc.4
IMAGE="/root/sneakers-appliance-$VERSION-amd64.qcow2"
```

## 2. Download the image and check it

```sh
cd /root
base="https://github.com/Sneakers-PAM/sneakers-appliance/releases/download/v$VERSION"
curl -fLO "$base/sneakers-appliance-$VERSION-amd64.qcow2"
curl -fLO "$base/sneakers-appliance-$VERSION-amd64.qcow2.sha256"
sha256sum -c "sneakers-appliance-$VERSION-amd64.qcow2.sha256"
```

`sha256sum` prints `OK`. To check the release's signature too, use
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) with the release public key:

```sh
curl -fLO "$base/sneakers-appliance-$VERSION-amd64.qcow2.sigstore.json"
curl -fL -o sneakers-release.pub "https://raw.githubusercontent.com/Sneakers-PAM/sneakers-appliance/v$VERSION/keys/production/cosign.pub"
cosign verify-blob --key sneakers-release.pub --insecure-ignore-tlog=true \
  --bundle "sneakers-appliance-$VERSION-amd64.qcow2.sigstore.json" "sneakers-appliance-$VERSION-amd64.qcow2"
```

It prints `Verified OK`, after a warning that the transparency log was skipped (the release key
signs without one).

## 3. Create the VM

```sh
qm create "$VMID" --name sneakers-appliance --ostype l26 \
  --machine q35 --bios ovmf \
  --efidisk0 "$STORAGE:1,efitype=4m,pre-enrolled-keys=0" \
  --tpmstate0 "$STORAGE:1,version=v2.0" \
  --cores 4 --memory 16384 \
  --scsihw virtio-scsi-single \
  --scsi0 "$STORAGE:0,import-from=$IMAGE,iothread=1" \
  --boot order=scsi0 \
  --net0 "virtio,bridge=$BRIDGE" \
  --agent enabled=1
```

What each part is for:

- `--machine q35 --bios ovmf`: a UEFI VM. The appliance boots only with UEFI.
- `--efidisk0 ...,pre-enrolled-keys=0`: the VM's firmware store starts **without** Secure Boot keys
  (Setup Mode), so the appliance can enrol its own. With Proxmox's pre-enrolled keys it would also
  trust Microsoft's keys, which the appliance never does, and it can't enrol its own.
- `--tpmstate0 ...,version=v2.0`: a TPM 2.0. The appliance seals its disk keys to it (full
  protection). Without one it asks to keep them in a key file instead (reduced protection).
- `--scsihw virtio-scsi-single` and `--scsi0 ...,import-from=...`: imports the image as the VM's
  disk on its own VirtIO SCSI controller.
- `--net0 virtio`: a VirtIO network card. `--agent enabled=1`: the QEMU guest agent (step 6).

To give the appliance more than 64 GiB, grow the disk now, before the first boot. The first boot
gives the extra space to its data and backup volumes:

```sh
qm disk resize "$VMID" scsi0 128G
```

Once the VM exists, the downloaded image isn't needed: `rm "$IMAGE"`.

## 4. First boot: Secure Boot keys

```sh
qm start "$VMID"
```

Open the VM's **Console** in the web UI. After a short while the appliance shows a **Secure Boot**
screen with **1. Use Secure Boot with the org keys (recommended)** selected. Press Enter.

It writes its keys, shows `Secure Boot keys enrolled. Restarting with Secure Boot on.` and restarts
by itself. Nothing is needed in the firmware menu.

To run without Secure Boot instead, type `no secure boot` and press Enter. The appliance then runs
with reduced protection, and you can turn Secure Boot on later from its admin page without a
reinstall.

## 5. Second boot: the TPM and setup

After the restart the appliance asks where to keep its disk keys, with **Use the TPM
(recommended)** selected. Press Enter. It formats its data volumes, then shows `Protection: full`,
the setup address (`https://<address>:8443`), the certificate fingerprint and a one-time setup code.

Open the address in a browser, check the fingerprint against the console, enter the code and follow
the setup steps: the first admin, recovery keys, and the rest.

## 6. The guest agent

The appliance runs the QEMU guest agent, so the VM's **Summary** shows its IP addresses, a backup
can freeze its file systems, and **Shutdown** and **Reboot** in Proxmox stop the appliance cleanly.
From the host:

```sh
qm agent "$VMID" ping
qm guest cmd "$VMID" network-get-interfaces
qm shutdown "$VMID"
```

`ping` prints nothing when the agent answers. `qm shutdown` stops the appliance's services in order
and powers it off; it can take a few minutes. The agent answers only those kinds of requests: it
refuses to run programs, read or write files, or set passwords (`qm guest exec` fails), so the
Proxmox host gets no way into the appliance that its admins don't have.

## If something goes wrong

- **The Secure Boot screen has no default and says the firmware isn't in Setup Mode:** the EFI disk
  was made with pre-enrolled keys. Power the VM off (`qm stop "$VMID"`), replace the EFI disk and
  start again:

  ```sh
  qm set "$VMID" --delete efidisk0
  qm set "$VMID" --efidisk0 "$STORAGE:1,efitype=4m,pre-enrolled-keys=0"
  qm start "$VMID"
  ```

- **The appliance says the box has no TPM:** the VM has no TPM state disk. Stop it and add one with
  `qm set "$VMID" --tpmstate0 "$STORAGE:1,version=v2.0"` before you continue, or press Enter to keep
  the keys in a key file (reduced protection).
- **The console shows a firmware screen or `BdsDxe: No bootable option`:** the boot order doesn't
  name the disk. Run `qm set "$VMID" --boot order=scsi0` and start the VM again.
- **`qm agent "$VMID" ping` says the agent isn't running:** the appliance starts the agent once it's
  past the Secure Boot screen; wait for the second boot. Check `--agent enabled=1` with
  `qm config "$VMID"`.
- **The console's text is small, or a code is hard to read:** OVMF usually starts the screen at
  800x600, so the appliance uses a smaller font (66x27). At 1024x768 it uses its large font (64x24).
  The setting stays on the VM's EFI disk, so you only do this once, and it doesn't affect the disk
  keys sealed to the TPM:

  1. Stop the VM with `qm shutdown "$VMID"`, open its **Console** and click **Start Now**.
  2. When the Proxmox logo shows, press Esc until the firmware menu opens.
  3. Open **Device Manager**, then **OVMF Platform Configuration**.
  4. Set **Change Preferred Resolution for Next Boot** to **1024x768**, then pick **Commit Changes
     and Exit**.
  5. Press Esc until you're back at the main menu, then pick **Reset**.
