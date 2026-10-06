# Output formats

Every format starts from the same installed disk image ([disk-layout.md](disk-layout.md)), written
from the verified copy of the release.

| `--format` | Arch | Output | Needs |
|---|---|---|---|
| `raw` | amd64 | `sneakers-<ver>-<arch>.raw`: the installed disk, sparse | nothing |
| `ova` | amd64 | `sneakers-<ver>-<arch>.ova`: OVF, manifest and stream-optimized VMDK | `qemu-img` |
| `qcow2` | amd64 | `sneakers-<ver>-<arch>.qcow2` and `proxmox-vm.md` | `qemu-img` |
| `iso` | amd64 | the install ISO | arrives with the install mode |
| `rpi` | arm64 | the Raspberry Pi image | arrives with the arm64 build |

The kit's container carries `qemu-img`; a bare kit binary reports `KIT_TOOL_MISSING` without it.
Lab builds add `-LAB` to every name.

## OVA (VMware)

- `vmx-19` (ESXi 7.0 U2 and later), 4 vCPU and 16 GiB by default (change them after import), one
  thin disk of `--disk-size` on a PVSCSI controller, one vmxnet3 NIC, EFI firmware, no vTPM (add one
  after import when the vCenter has a key provider; the box then runs in TPM mode).
- `uefi.secureBoot.enabled=FALSE` and, for the first boot, `uefi.allowAuthBypass=TRUE`. Before the
  first boot, delete the PK in the VM's firmware setup ([secure-boot.md](secure-boot.md)); after the
  keys are enrolled, turn Secure Boot on and remove `uefi.allowAuthBypass`.
- The manifest (`.mf`) carries the SHA-256 of the OVF and the VMDK. The OVA isn't signed with an OVF
  certificate: the trust that matters is in the boot chain.

## qcow2 (Proxmox VE and KVM)

`qemu-img convert -O qcow2` of the installed disk, with `proxmox-vm.md`: the `qm` commands for a q35
VM with OVMF and an EFI disk without pre-enrolled keys (so the box enrols the org keys itself), a
v2.0 TPM state disk, VirtIO SCSI single, a VirtIO NIC and the guest agent.
