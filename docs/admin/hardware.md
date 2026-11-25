# Hardware and firmware

## Needed

- x86-64 with hardware virtualization, UEFI and Secure Boot. Legacy BIOS does not work.
- A TPM 2.0 with SHA-256 PCRs. Without one the first boot stops.
- A system disk with 512-byte logical sectors. The whole disk is used.
- Console access (a BMC's remote console or a screen): the recovery key can only be typed there.

Tested in virtual machines only so far, not on server hardware.

## Firmware settings

| Setting | Value | Why |
|---|---|---|
| Boot mode | UEFI only | |
| Virtualization (VT-x or AMD-V) | on | instances |
| TPM | on | node identity, disk key |
| Secure Boot | Setup Mode to enroll, then on | see [disk encryption](disk-encryption.md) |
| Option ROMs of network cards, GPUs, RAID cards and HBAs | off | see below |
| Network boot | off, except to install | it runs the card's option ROM |
| Firmware administrator password | set | or anyone at the console can turn Secure Boot off |

## Option ROMs

An option ROM is a small driver on a card that the **firmware** runs before any operating system. It is
usually signed with a vendor key that also signs many other programs. If one ran,
`torngat-seal-root` refuses: another program signed with that key, if vulnerable, might unlock
the disk.

Turning the option ROM off does not turn the card off. The firmware does not use the card, but Linux
starts its own driver and the card works.

| Card | Lost when its option ROM is off |
|---|---|
| Network card | booting from the network through it |
| RAID card, HBA | booting from its disks, and its setup menu. The disks appear in Linux |
| GPU | its picture before Linux starts. Use the BMC's console. A few GPUs, mostly main displays, need their ROM |
| NVMe in a slot | normally nothing: the firmware has its own driver |

Choose "option ROM: disabled", not "slot: disabled". Built-in network ports often have a separate
"network stack" or "PXE" setting.

If the machine must boot from such a card, use `torngat-seal-root --allow-other-signers` and keep the
revocation list (`dbx`) current. A stolen disk without its machine stays protected; someone with
physical access to the machine might get at it.

| Machine | Flag usually needed |
|---|---|
| Boots from built-in NVMe or SATA, option ROMs off | no |
| Network boot left on | yes |
| System disk behind a RAID card or HBA | yes |
| GPU ROM runs at start | yes |

`torngat-seal-root` looks at what this machine really ran, so these are only expectations.
