# Troubleshooting

| Symptom | Meaning | What to do |
|---|---|---|
| `access denied` from the firmware | the image is not signed with an enrolled key | enroll the key, or use the right image (`--dev` images have their own key) |
| Asks for a recovery key or passphrase at boot | the TPM refused | [changes](changes.md), then [reseal](disk-encryption.md#resealing). Unexpected: suspect tampering |
| Stops with "the root account is locked" | the boot failed; there is no emergency shell, on purpose | read the messages above it |
| `make-root: the root partition is missing or not encrypted` | something replaced the root | check the disk |
| `make-root: ... root.key ... is damaged` | the only key of a node without a TPM | restore it from its backup |
| `make-root: two copies of this image are attached` | a stick or second disk has the same image | remove it, reboot |
| `make-root: cannot tell whether there is a TPM` | firmware problem | check the firmware settings |
| `make-root: line N failed` | often a TPM that does not work | check the TPM in the firmware |
| Asks for a passphrase, on a node without a TPM | its key file is gone, or a TPM was turned on | restore the file, or turn the TPM off |
| `root-barrier: ...` | the TPM could not be written to, or the disk header was changed | suspect tampering |
| `torngatd init`: root "is not sealed" | `torngat-seal-root` was not run | run it |
| `torngat-seal-root`: "Secure Boot is not on" | | enroll the key and turn it on |
| ... "made before Secure Boot was on" | the key was enrolled in another way than with our tool | in Setup Mode, run `torngat-enroll-secure-boot` |
| ... "code signed by others" | an option ROM or another loader ran | it names the signer; turn [option ROMs](hardware.md#option-roms) off, reboot |
| ... "PCR 12 is not zero" | something changed the kernel command line | find what (firmware, BMC); suspect tampering |
| ... "does not match PCR 7" | the firmware's event log is wrong | firmware update; suspect tampering |
| ... "unexpected key slots" | someone added a key to the disk | reinstall |
| ... "a factory reset is requested" | | reboot first: it makes the root anew |
| `torngat-enroll-secure-boot`: "no db entries" | the vendor keys were cleared too | restore the factory keys, then clear only the platform key |
| ... "already set up" | enrolling would erase the node | reinstall it |
| `the TPM refused the node key` | TPM cleared or replaced | join again as the message says, under a new name. A controller: [restore](backup.md) a backup |
| `node name is already in use` | the name was used before | another `--name` |
| `platform.key` is missing, malformed, or not this cluster's | the file was lost, damaged or replaced | put the right file back: the volumes depend on it ([storage](storage.md#volume-keys)) |
| `no record of their platform key` | the store was changed or damaged | suspect tampering; do not make a new platform key |
| `there is no recovery code` | the cluster was made before they existed | [make one](backup.md#recovery-code) |
| `wrong recovery code, or a damaged or forged backup` | | check the file; a code made later does not open earlier backups |
| `vgs` shows nothing | the disk is not in LVM's list, on purpose | [storage](storage.md#nothing-is-opened-by-itself) |
| `modprobe zfs`: "Key was rejected" | the module was not signed by this image's key, or the key is not enrolled | rebuild the image; enroll the key |
| `zpool import`: "in use from another system" | another machine had the pool, or the root was made anew | [storage](storage.md#nothing-is-opened-by-itself) |
| a pool: `no storage driver on this node` | no LVM or ZFS driver yet | |
| a pool: `volume(s) on the storage that the platform does not know` | left by a deleted cluster, a restore, or by hand | look at them; Torngat never deletes them |
| a volume: `the encryption header is gone` or `unknown data where the encryption header goes` | the start of the device was overwritten | the data cannot be read; delete the volume |
| a volume: `key refused` | the node is not active, or no instance on it uses the volume | [nodes](nodes.md) |
| an instance: `instances need the agent to run as root` | `torngatd` was started by hand as another user | run it as root, or through its service |
| an instance: `qemu failed to start: ...` | QEMU's last messages follow | `journalctl -u torngat-vm-<uid>` |
| `/dev/kvm` missing | virtualization is off | turn it on in the firmware |

To look at a node: `journalctl -b`, `systemctl --failed`, `bootctl status`, `systemd-cryptenroll <root
partition>` (a sealed root has one `recovery` and one `tpm2` slot, nothing else).
