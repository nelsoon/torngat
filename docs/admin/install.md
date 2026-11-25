# Install a node

1. Set the firmware up: [hardware](hardware.md).
2. Build the image and write it to the system disk: [host image](../../image/README.md). This erases the
   disk. Never use a `--dev` image outside a lab: anyone at the console is root.
3. In the firmware setup, clear the **platform key** only. The machine is then in Setup Mode.
4. Boot. The first boot creates the root file system. Log in with SSH (DHCP address, key given to
   `build.sh --authorized-keys`; there is no password).
5. Enroll the Secure Boot key, and reboot. **This erases the root file system**, and the SSH host
   keys change:

   ```sh
   torngat-enroll-secure-boot
   reboot
   ```

6. Check that Secure Boot is on, then seal. Store the recovery key somewhere else:

   ```sh
   bootctl status
   torngat-seal-root
   ```

7. Set the node up. On the first one:

   ```sh
   torngatd init
   systemctl start torngatd
   ```

   On the others, see [nodes](nodes.md). `torngatd` starts by itself at every boot from then on.

8. Reboot once. The node must come back without asking for anything.

## Ports

| Port | Where | Use |
|---|---|---|
| 7443/tcp | controller | control connections from nodes (mutual TLS) |
| 7444/tcp | controller | joining |
| 8080/tcp | controller, loopback only | API (no TLS yet: use an SSH tunnel) |
| 22/tcp | every node | SSH |

Put them on a management network.
