# Administrator guide

Torngat is pre-alpha: do not run untrusted tenants or data you cannot lose on it.

1. [Hardware and firmware](hardware.md): what to buy, what to set in the firmware before installing
2. [Install a node](install.md)
3. [Secure Boot, TPM and the recovery key](disk-encryption.md)
4. [Nodes and join tokens](nodes.md)
5. [Updates and changes](changes.md): what is safe, and what asks for the recovery key
6. [Storage for instances](storage.md): LVM, building with ZFS
7. [Networks](networks.md): host networks, provider networks
8. [Back up and restore the cluster](backup.md)
9. [Troubleshooting](troubleshooting.md)

## The things to remember

1. Put the system disk on built-in NVMe or SATA, and turn option ROMs off for other cards.
2. Keep the vendor's Secure Boot keys; clear only the platform key.
3. Enroll the key **before** setting up the node: it erases the root file system.
4. The recovery key is shown once. Store it away from the machine. Without
   it, a TPM or Secure Boot change means reinstalling the node.
5. Until it is sealed, a machine must stay in trusted hands.
6. A Secure Boot key or `dbx` update makes the TPM refuse at the next boot. Have the recovery key and
   console access ready first.
7. An unexpected recovery key prompt may be an attack: find the cause before typing it.
8. A stolen disk is protected. A whole stolen server is not: it boots by itself.
9. Before a node leaves your hands, [erase its disk keys](changes.md#retire-a-node).
10. The admin token can do everything. Never share or log it.
11. The cluster's recovery code is shown once by `torngatd init`. Without it and a [backup](backup.md), a lost controller loses
    every volume.
