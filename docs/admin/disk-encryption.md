# Secure Boot, TPM and the recovery key

The root file system holds the node's identity and, on a controller, the cluster's store and CA key.
It is encrypted (LUKS2).

## What unlocks it

The TPM, by itself, if all of this holds:

- Secure Boot is in the state it had at sealing: on, with the same keys (PCR 7);
- the kernel, initrd and command line are a file with a policy we signed, and it is still in its initrd
  (PCR 11);
- nothing was added to the command line, nor credentials or extensions (PCR 12, 13);
- no root was opened yet (PCR 15).

Otherwise the console asks for the recovery key.

## What it protects

| Situation | Protected |
|---|---|
| Disk stolen or returned to its vendor | yes |
| Disk in another machine, or another system booted on this one | yes |
| Kernel command line or initrd changed | yes |
| Whole server stolen | no: it boots by itself |
| Someone boots an old, vulnerable image signed with our key | no rollback protection yet |
| Data on the disk modified by someone who has it | not detected |
| Anything before `torngat-seal-root` | no: keep the machine in trusted hands |

## Recovery key

- Shown once by `torngat-seal-root`. Store it offline or in a password manager, with the node's name.
- On a terminal it asks for the last 8 letters, to make sure you have them. If you mistyped, run it again:
  it makes a new key.
- Lost, with a TPM that still unlocks: reinstall the node at a moment you choose.
- Lost, with a TPM that refuses: the node's data is gone. Reinstall.

## Resealing

After typing the recovery key at boot:

1. Find out why the TPM refused (see [changes](changes.md)). With no explanation, do not go on: treat the
   machine as tampered with.
2. Accept the new state:

   ```sh
   torngat-seal-root --reseal
   ```

3. Reboot to check.

## Without a TPM

Make sure first that the TPM is not just turned off in the firmware. If there is none when the root is created,
its key is a file on the boot partition, `torngat/root.key`:

- The node boots by itself, and **anyone with the disk can read it**, including the node's identity and, on
  a controller, everything.
- It must be accepted: `torngatd init --tpm optional --allow-unsealed-root` (first node), or on a cluster that
  allows nodes without a TPM, `torngatd join --tpm off --allow-unsealed-root`. The node shows the
  trait `disk-not-protected` in the API.
- The file is the **only** key and there is no recovery key. Back it up; without it the node's data is gone. To
  read it, mount the boot partition (the first one on the disk).
- Adding or turning on a TPM later locks the node. Turn it off again, or reinstall to use it.
- `torngat-enroll-secure-boot` is still useful, but `torngat-seal-root` refuses.

A node that was sealed never falls back to this: with its TPM off or broken it asks for the recovery key.
