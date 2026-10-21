# Migrating from another client

This page explains how to move validators from Lighthouse, Prysm, Teku, Nimbus or Lodestar to
Grandine, and how to move a Grandine installation to another machine. The procedure is the same in
every case: the new setup must be fully ready, the old validator client must be stopped for good,
and the slashing protection history must travel with the keys.

> **Warning:** The real risk in a migration is slashing. A validator is slashed if the same key
> signs conflicting messages, and that happens when two validator clients run the same keys, even
> for one slot, or when the new client starts without the old client's signing history. Losing a
> few epochs of rewards while you migrate costs very little. Getting slashed costs a lot. Never
> rush this.

Practice the whole procedure on the Hoodi testnet first if you can.

## Overview

1. Install Grandine and sync a Grandine beacon node, while the old client keeps validating.
2. Stop the old validator client and make sure it cannot start again.
3. Export the slashing protection history from the old client.
4. Wait until the last messages signed by the old client are finalized (at least two epochs).
5. Import the slashing protection history into Grandine.
6. Make the validator keystores available to Grandine.
7. Start Grandine with the validators, and check that they attest.
8. Remove the keys from the old client.

## Step 1: Sync Grandine first

Set up Grandine next to your current client, on the same machine or a new one, and let it sync
before you touch the validators. Checkpoint sync takes minutes.

```bash
grandine bn \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --checkpoint-sync-url https://CHECKPOINT-HOST
```

If Grandine runs on the same machine as the old beacon node, choose ports that do not clash, for
example `--libp2p-port 9100 --discovery-port 9100 --quic-port 9101 --http-port 5152`. An execution
client serves one consensus client, so a second beacon node needs its own execution client, or you
switch the execution client over during the migration.

Wait until Grandine follows the head of the chain. See [Quick start](./quick_start.md),
[Checkpoint sync](./checkpoint_sync.md) and [Connecting an execution client](./execution_client.md).

## Step 2: Stop the old validator client

Stop the old validator client, or the old beacon node if its validator client runs inside it, as
with Nimbus. Disable the service so that a reboot or a process manager cannot start it again:

```bash
sudo systemctl stop OLD-VALIDATOR-SERVICE
sudo systemctl disable OLD-VALIDATOR-SERVICE
```

With Docker, also remove any `restart:` policy or the container itself, so Docker does not
restart it.

Then check that it is really gone:

```bash
ps aux | grep -E "lighthouse|prysm|validator|teku|nimbus|lodestar" | grep -v grep
```

Also check that no other machine, backup server or old Docker host runs these keys.

## Step 3: Export slashing protection from the old client

Export the slashing protection history in the [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076)
interchange format. Run the export after the client has stopped, so that the history is complete.
The commands below follow each client's documentation, linked under each one; check it for the
exact paths and flags of your version.

### Lighthouse

```bash
lighthouse account validator slashing-protection export slashing_protection.json \
  --network mainnet \
  --datadir /path/to/lighthouse/datadir
```

See [Lighthouse: slashing protection](https://lighthouse-book.sigmaprime.io/validator_slashing_protection.html).

### Prysm

```bash
prysm.sh validator slashing-protection-history export \
  --datadir=/path/to/prysm/validator/datadir \
  --slashing-protection-export-dir=/path/to/export-dir
```

`--datadir` is the directory that contains Prysm's `validator.db`. Prysm writes
`slashing_protection.json` into the export directory. See
[Prysm: import and export slashing protection history](https://prysm.offchainlabs.com/docs/backup-and-migration/slashing-protection/).

### Teku

```bash
teku slashing-protection export \
  --data-path=/path/to/teku/data \
  --to=/path/to/slashing_protection.json
```

Use the same `--data-path` (or `--data-validator-path`) that the Teku validator client ran with.

### Nimbus

```bash
nimbus_beacon_node slashingdb export slashing_protection.json \
  --data-dir=/path/to/nimbus/data
```

If the validators were in a non-default directory, add `--validators-dir`. See
[Nimbus: migrate from Nimbus](https://nimbus.guide/migration-options.html).

### Lodestar

```bash
lodestar validator slashing-protection export \
  --network mainnet \
  --dataDir /path/to/lodestar/data \
  --beaconNodes http://BEACON-NODE:9596 \
  --file slashing_protection.json
```

Lodestar reads the genesis validators root from a beacon node, by default
`http://127.0.0.1:9596`, so point `--beaconNodes` at any synced beacon node of the same network,
Grandine included. Do not use `--force`: it writes a zero genesis validators root, and Grandine
rejects a file whose root does not match the network. See the
[Lodestar validator CLI reference](https://chainsafe.github.io/lodestar/run/validator-management/validator-cli/).

Check that the file contains your validators before you continue:

```bash
jq '.data | length' slashing_protection.json
jq -r '.data[].pubkey' slashing_protection.json
```

## Step 4: Wait for finality

Wait at least two epochs (about 13 minutes on mainnet) after the old validator client stopped,
until the last epoch it signed for is finalized. Check on a block explorer that your validators
have missed their latest attestations; that shows the old client is no longer signing.

## Step 5: Import slashing protection into Grandine

Grandine must be stopped while you import. Use the same `--network` and `--data-dir` that Grandine
runs with, before the `interchange` subcommand:

```bash
grandine --network mainnet interchange import slashing_protection.json
```

With a custom data directory:

```bash
grandine --network mainnet --data-dir /var/lib/grandine interchange import slashing_protection.json
```

Grandine logs `interchange file imported (imported records: N, failed records: M)`. If `failed
records` is not 0, find out why before you continue (each failed record is logged at debug level). A
file from another network is rejected as a whole: Grandine checks the file's genesis validators root
against the network and stops with `incorrect genesis validators root`.

With Docker:

```bash
docker run --rm \
  -v $HOME/.grandine:/root/.grandine \
  -v $(pwd)/slashing_protection.json:/tmp/slashing_protection.json:ro \
  sifrai/grandine:stable \
  --network mainnet interchange import /tmp/slashing_protection.json
```

The history goes into `{data-dir}/{network}/validator/slashing_protection.sqlite`, which both the
integrated validator client and `grandine vc` use. See [Slashing protection](./slashing_protection.md)
and [Subcommands and tools](./subcommands.md).

## Step 6: Give Grandine the keystores

Grandine loads EIP-2335 keystores from a directory given with `--keystore-dir`. It reads the files
directly in that directory (files ending in `.json`, or without an extension), not subdirectories.

The simplest source is the original `validator_keys` directory created by the deposit CLI, with the
keystore password:

```bash
mkdir -p /var/lib/grandine/keys
cp /path/to/validator_keys/keystore-m_*.json /var/lib/grandine/keys/
printf '%s' 'KEYSTORE-PASSWORD' > /var/lib/grandine/keystore-password.txt
chmod 600 /var/lib/grandine/keystore-password.txt
```

If the keystores have different passwords, use `--keystore-password-dir` with one file per
keystore, named like the keystore but ending in `.txt` instead of `.json`.

Other clients store imported keystores in their own layouts, often one directory per validator,
and may have re-encrypted them with a different password. If you do not have the original files,
copy each keystore out of the old client's directory into one flat directory and use the password
that the old client was given at import.

Alternatively, import keys with the slashing protection in one request through the
[Keymanager API](./keymanager_api.md), once Grandine runs with `--enable-validator-api`.

If you use a remote signer, point Grandine at it instead. See [Web3Signer](./web3signer.md).

See [Managing validator keys](./key_management.md) for details.

## Step 7: Start Grandine with the validators

Start Grandine with the keys. With the integrated validator client:

```bash
grandine \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --keystore-dir /var/lib/grandine/keys \
  --keystore-password-file /var/lib/grandine/keystore-password.txt \
  --suggested-fee-recipient FEE-RECIPIENT-ADDRESS \
  --track-liveness \
  --detect-doppelgangers
```

`--detect-doppelgangers` makes Grandine watch the network for a few epochs before it signs, and
stop if it sees your validators active elsewhere. With the built-in beacon node it requires
`--track-liveness`. It costs a few epochs of missed attestations, which is a good trade during a
migration. See [Doppelganger protection](./doppelganger_protection.md).

Carry over your settings from the old client: fee recipient, graffiti, gas limit and builder
(MEV) configuration. See [Fee recipient, graffiti and gas limit](./fee_recipient.md) and
[Builder API and MEV](./builder_api_and_mev.md).

Then check that the validators are loaded and attesting: watch the logs, a block explorer and your
[metrics](./metrics.md). See [Monitoring validator performance](./validator_monitoring.md).

## Step 8: Clean up the old client

Once Grandine has validated for a while, delete the keys from the old client's data directory, so
the old client can never sign with them again, even if someone starts it by mistake. Keep the
exported slashing protection file with your backups. You can then remove the old beacon node.

## Migrating Grandine to another machine

The same rules apply when you move Grandine itself: sync the new machine first, stop the old one for
good, and move the slashing protection history with the keys.

1. **Prepare the new machine.** Install Grandine and an execution client, and sync with
   checkpoint sync. If you prefer to copy the beacon database instead of syncing, stop the old node
   and copy `{data-dir}/{network}/beacon`. The beacon database is not needed for safety; a fresh
   checkpoint sync is often faster than copying it.
2. **Stop Grandine on the old machine** and disable its service, as in step 2.
3. **Export slashing protection** on the old machine:

   ```bash
   grandine --network mainnet interchange export slashing_protection.json
   ```

   You can also copy `{data-dir}/{network}/validator/slashing_protection.sqlite` while Grandine is
   stopped. The interchange file is the safer choice when versions differ.
4. **Copy the keys and settings**: the keystores and password files, `validators.yml` from the
   validator directory (it holds per-validator settings such as fee recipients), the secrets
   directory if you imported keys through the Keymanager API, and the API token file if you use the
   validator API. See [Default ports and paths](./default_ports.md) for the layout.
5. **Wait at least two epochs.**
6. **Import slashing protection** on the new machine:

   ```bash
   grandine --network mainnet interchange import slashing_protection.json
   ```

7. **Start Grandine** on the new machine with `--detect-doppelgangers` and `--track-liveness`, and
   check that the validators attest.
8. **Wipe the keys** from the old machine.

To keep the same peer identity on the new machine, copy the network key from
`{data-dir}/{network}/network/key`. This is optional; a new key only means a new peer ID.

> **Warning:** Never copy the whole data directory to the new machine while the old machine keeps
> running, and never run two machines from copies of the same data directory. Both would sign with
> the same keys.

## Moving from Grandine to another client

Reverse the procedure: stop Grandine for good, export with
`grandine --network mainnet interchange export slashing_protection.json`, wait two epochs, and
import the file into the other client following its documentation.

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--keystore-dir`: default none. Directory with EIP-2335 keystore files. Requires a password option.
- `--keystore-password-file`: default none. File with the password for all keystores.
- `--keystore-password-dir`: default none. Directory with one password file per keystore.
- `--detect-doppelgangers`: default disabled. Watch the network before signing and stop if the keys are active elsewhere.
- `--track-liveness`: default disabled. Track validator liveness; required by `--detect-doppelgangers` with the built-in beacon node.
- `--data-dir`: default `$HOME/.grandine`. Parent directory of the per-network data directories.
- `--slashing-protection-history-limit`: default `256`. Epochs of slashing protection history to keep.
