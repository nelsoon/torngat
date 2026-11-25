# Updates and changes

Does a sealed node still boot by itself afterwards?

| Change | Boots by itself |
|---|---|
| Platform extension (`torngat-install-extension FILE`), no reboot needed | yes |
| New kernel, initrd, command line or boot loader signed with the same keys | yes, but see below |
| Firmware update | usually |
| Instances, networks, disks other than the system disk | yes |
| Revocation list (`dbx`) or other Secure Boot key update, from the firmware or a tool | **no** |
| Secure Boot turned off | **no** |
| Option ROM turned on or off, or a card with one added or removed | **may not** |
| TPM cleared or replaced, mainboard replaced, disk moved | **no** |
| New image signed with another Secure Boot key or PCR policy key | **no** |

There is no tool to update the image in place yet. Writing a new image to the disk **erases the node**.

For **no** and **may not**:

1. Have the recovery key and the console ready. Do one node at a time.
2. Make the change, reboot, type the recovery key.
3. `torngat-seal-root --reseal`, and reboot to check.

A TPM that was cleared or replaced, or a disk moved to another machine, also loses the node's identity: join
it again (`torngatd` explains what to do). On a controller, that identity cannot be joined again: reinstall
the cluster.

Keep the signing keys (`image/keys`) safe and backed up. Who has them can make an image that unlocks every
node; without them no update can be made.

## Retire a node

There is no API for it yet. Stop its instances, then erase its disks. For the root file system it is
enough to erase the key slots, which **cannot be undone**:

```sh
cryptsetup erase <root partition>
```
