# Back up and restore the cluster

A backup has the cluster's CA, its platform key and its store: nodes, projects, instances, volumes, wrapped volume keys.
It does **not** have the data on volumes, nor the admin token.

## Recovery code

`torngatd init` shows it once. It opens the backups, and only it does: the cluster cannot read the backups it made.

- Store it away from the cluster, and not with the backups. **Whoever has both a backup and the code controls the
  cluster.**
- Lost, or on a cluster that has none: stop `torngatd` (instances keep running) and make another. Earlier backups still need the old one.

  ```sh
  systemctl stop torngatd
  torngatd new-recovery-code
  systemctl start torngatd
  ```

A new code does not close old backups. If the old code leaked, destroy them; whoever could also change the store can bring
the old code back.

## Back up

On the controller, as root, while it runs. Use `umask 077`. Copy the file elsewhere, every day and after important changes:

```sh
curl -fsS --config <(printf 'header = "Authorization: Bearer %s"\n' "$(cat /var/lib/torngat/admin-token)") \
  -o torngat-backup http://127.0.0.1:8080/v1/platform/backup
```

A backup opens only whole and unchanged. Test restoring from time to time, on a machine with no network.

## Restore

1. Make sure that the old controller is off and never comes back: two at once corrupt the cluster.
   If it was stolen, do not restore: its disk may hold the CA and platform keys. Reinstall.
2. [Install](install.md) a node up to sealing it, with the **old controller's address**, and the new disks or the old ones with the volumes.
3. Check the backup's date when asked, then go on:

   ```sh
   torngatd restore --backup torngat-backup
   systemctl start torngatd
   ```

If it fails halfway, remove what it made in `/var/lib/torngat` before trying again.

The controller keeps its name, and gets a new identity and a new admin token. Other nodes connect again by themselves.

The cluster is then as it was at the backup:

- **Instances made since then are stopped** on their nodes, and deleted ones start again: use the latest backup.
- Volumes made since then are unknown, and their keys are gone: their data is lost.
- A node that joined since then must join again: on it, stop `torngatd`, remove `node.json` and `identity` from
  `/var/lib/torngat`, and use a new token. One that was removed since then is accepted again.
- The keys of volumes deleted since then come back. Delete old backups that you no longer need.
- Join tokens do not come back: make new ones.
- Settings are those of then, such as whether nodes need a TPM.
