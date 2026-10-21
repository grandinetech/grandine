# Updating Grandine

Keep Grandine up to date. New releases fix bugs, improve performance and, before every network
upgrade (hard fork), add the rules of the new fork. A node that is not updated before a hard fork
follows the wrong chain from the fork epoch on, and its validators miss all duties.

## Release channels

| Channel | Where | Source | Use it for |
| --- | --- | --- | --- |
| Stable | GitHub releases, Docker `latest`, `stable` and `VERSION` tags | Plain version tags such as `3.0.0` | Mainnet |
| Pre-release | GitHub releases, Docker `unstable` and `VERSION` tags | Tags with a suffix such as `3.0.0-rc.0` | Testnets, early testing of a coming release |
| Unstable | Docker `unstable` tag only | Every commit to the `develop` branch | Testing the newest code |

GitHub releases are drafted by the release workflow and published by the team with release notes.
Read the notes before you update: they say whether a release is required for a hard fork and whether
it changes any options.

### Release notifications

- On [GitHub](https://github.com/grandinetech/grandine), choose **Watch**, then **Custom**, then
  **Releases** to get an email for every release.
- Follow the announcements on the [Grandine Discord](https://discord.gg/H9XCdUSyZd) or
  [Grandine Telegram](https://t.me/+yMHjrJanClozYzQ0).

## How urgent is an update?

Decide when to update from the release notes:

| Release type | Validators on Mainnet | Beacon node only | Testnets |
| --- | --- | --- | --- |
| Hard fork support for your network | Required before the fork epoch | Required before the fork epoch | Required before the fork epoch |
| Security fix | As soon as possible | As soon as possible | As soon as possible |
| Bug fix that affects your setup | Within days | Within days | When convenient |
| Features and performance | When convenient | When convenient | When convenient |

> **Tip:** Update during a quiet period. Use the [Beacon Node API](./beacon_node_api.md) or a block
> explorer to check that none of your validators has a block proposal in the next few minutes. A
> restart usually costs at most one or two missed attestations.

## Check the version you run

The binary prints its version:

```bash
grandine --version
```

```text
Grandine 3.0.0
```

A running node reports its version, with the commit and platform, through the API:

```bash
curl -s http://localhost:5052/eth/v1/node/version
```

```json
{"data":{"version":"Grandine/3.0.0-6a37d7fa/x86_64-linux"}}
```

`/eth/v2/node/version` also reports the version of the connected execution client.

## Update a binary

1. Download the new binary, or [build it from source](./build_from_source.md). See
   [Pre-built binaries and Docker](./downloads.md).

2. Stop Grandine and wait for it to exit. Grandine saves its chain on shutdown and logs
   `saving current chain before exit…`:

   ```bash
   sudo systemctl stop grandine
   ```

3. Replace the binary:

   ```bash
   sudo install -m 0755 grandine-VERSION-linux-x64 /usr/local/bin/grandine
   grandine --version
   ```

4. Start Grandine again and watch the logs:

   ```bash
   sudo systemctl start grandine
   sudo journalctl -fu grandine
   ```

To keep the downtime short, download the new binary before you stop the old one. Keep the old binary
until you are sure the new one works.

## Update a Docker container

If you use the `stable` tag, pull it again. If you pinned a version tag, change it to the new version
first:

```bash
docker pull sifrai/grandine:stable
docker stop grandine && docker rm grandine
# Start the container again with the same options.
```

With Docker Compose, change the image tag in `docker-compose.yml`, then run:

```bash
docker compose pull grandine
docker compose up -d grandine
```

Docker stops the container with `SIGTERM` and kills it after a timeout. Give Grandine enough time to
save its state, for example with `stop_grace_period: 2m` in Compose or `docker stop -t 120`. See
[Running as a service](./running_as_a_service.md).

## Database compatibility

Grandine records the format of its data directory in a `meta.json` file directly in the network's data
directory, for example `~/.grandine/mainnet/meta.json`:

```json
{
  "application": "Grandine",
  "schema_version": "0.2.3"
}
```

On every start, Grandine reads this file and:

- refuses to start if the directory belongs to a different application;
- accepts any schema version: the compatibility check against `0.2.0` is currently skipped, so even
  data from before the move from RocksDB to `libmdbx` is not rejected;
- updates the recorded schema version to its own if it differs, and logs
  `using schema version 0.2.3 for new data`.

Upgrades within the same schema series need no migration and no resync. Grandine reads data written
by older versions and writes new data in the current format. The slashing protection database
(`validator/slashing_protection.sqlite`) is migrated forward automatically on start.

If a release ever needs a resync or a manual migration, its release notes say so.

## Downgrading

Downgrading is sometimes needed when a new release has a problem. Grandine does not block a
downgrade within the same schema series, but an older version may not understand data that a newer
version wrote. Plan for it:

1. **Before you upgrade**, export the slashing protection data. This is cheap insurance for any
   change:

   ```bash
   sudo systemctl stop grandine
   grandine --network mainnet interchange export slashing-protection-backup.json
   ```

   Pass the same `--data-dir` as the node uses if it is not the default. See
   [Slashing protection](./slashing_protection.md).

2. **To downgrade**, stop Grandine, install the older binary or image, and start it.

3. **If the older version fails to load the database**, resync the beacon database. The fastest way
   is a fresh [checkpoint sync](./checkpoint_sync.md):

   ```bash
   grandine --network mainnet \
     --eth1-rpc-urls http://127.0.0.1:8551 \
     --jwt-secret /path/to/jwt.hex \
     --checkpoint-sync-url CHECKPOINT-URL \
     --force-reset-beacon-db
   ```

   `--force-reset-beacon-db` deletes the `eth1_cache`, `beacon_fork_choice`, `pubkey_cache` and `sync`
   databases on startup. It does not touch the validator directory or the slashing protection
   database. Remove the option after this start, or Grandine resets the database on every start.

4. **If the slashing protection database cannot be opened** by the older version, move it aside and
   import the export from step 1 before you start validating. The slashing protection database has
   versioned schema migrations, and Grandine refuses to open a database that has a migration it
   does not know. So once a newer version adds a migration and applies it, older versions fail to
   start with that database:

   ```bash
   grandine --network mainnet interchange import slashing-protection-backup.json
   ```

> **Warning:** You cannot downgrade to a version that does not support the current fork of the
> network. After a hard fork, only versions that include it can follow the chain.

## Command line options

- `--version`: print the version and exit.
- `--force-reset-beacon-db`: default disabled. Delete the local beacon databases on startup for a fresh sync.
- `--checkpoint-sync-url`: no default. Beacon Node API URL to load a recent finalized checkpoint from.
- `--data-dir`: default `$HOME/.grandine`. Parent directory for data; the network name is appended.

See the [Command line reference](./cli_options.md) for the full list.
