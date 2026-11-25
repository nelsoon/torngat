# Troubleshooting

| Symptom | Meaning | What to do |
|---|---|---|
| `access denied` from the firmware | the image is not signed with an enrolled key | enroll the key, or use the right image (`--dev` images have their own key) |
| Asks for a recovery key or passphrase at boot | the TPM refused | [changes](changes.md), then [reseal](disk-encryption.md#resealing). Unexpected: suspect tampering |
| Stops with "the root account is locked" | the boot failed; there is no emergency shell, on purpose | read the messages above it |
| `make-root: the root partition is missing or not encrypted` | no TPM, or something replaced the root | check the TPM and the disk |
| `root-barrier: ...` | the TPM could not be written to, or the disk header was changed | suspect tampering |
| `torngatd init`: root "is not sealed" | `torngat-seal-root` was not run | run it |
| `torngat-seal-root`: "Secure Boot is not on" | | enroll the key and turn it on |
| ... "made before Secure Boot was on" | the key was enrolled in another way than with our tool | in Setup Mode, run `torngat-enroll-secure-boot` |
| ... "code signed by others" | an option ROM or another loader ran | turn [option ROMs](hardware.md#option-roms) off, reboot |
| ... "PCR 12 is not zero" | something changed the kernel command line | find what (firmware, BMC); suspect tampering |
| ... "does not match PCR 7" | the firmware's event log is wrong | firmware update; suspect tampering |
| ... "unexpected key slots" | someone added a key to the disk | reinstall |
| ... "a factory reset is requested" | | reboot first: it makes the root anew |
| `torngat-enroll-secure-boot`: "no db entries" | the vendor keys were cleared too | restore the factory keys, then clear only the platform key |
| ... "already set up" | enrolling would erase the node | reinstall it |
| `the TPM refused the node key` | TPM cleared or replaced | join again, as the message says |
| `/dev/kvm` missing | virtualization is off | turn it on in the firmware |

To look at a node: `journalctl -b`, `systemctl --failed`, `bootctl status`, `systemd-cryptenroll <root
partition>` (a sealed root has one `recovery` and one `tpm2` slot, nothing else).
