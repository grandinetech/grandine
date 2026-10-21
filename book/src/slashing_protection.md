# Slashing protection

A validator is slashed when it signs two conflicting messages: two different blocks for the same
slot, two attestations with the same target epoch, or one attestation that surrounds another.
Slashing destroys part of the stake and forces the validator out of the network. It almost always
happens to honest operators who run the same key in two places, or who move a key without its
signing history.

Grandine keeps a local record of everything each validator has signed and refuses to sign anything
that conflicts with it. This record is the slashing protection database. It is always on, for local
keystores and for keys held by a [Web3Signer](./web3signer.md).

## How it works

Before Grandine signs a block or an attestation, it checks the message against the database and
stores it in the same transaction:

- **Blocks.** A second block for a slot that already has a different signed block is rejected. So is
  a block for a slot lower than the lowest slot on record for that validator.
- **Attestations.** An attestation is rejected if it has the same target epoch as a stored one with a
  different signing root, if it surrounds a stored attestation or is surrounded by one, or if its
  source or target epoch is lower than the lowest one on record.
- **Clock.** Grandine stores the current epoch. If the system clock goes back to an earlier epoch,
  it refuses to sign until the clock catches up.

Identical messages (same slot or target and same signing root) are not signed twice either. When a
message is refused, Grandine logs a warning such as:

```text
slashing protector rejected slashable attestation (error: invalid attestation ...)
slashing protector rejected slashable beacon block (error: duplicate signed beacon block proposal ...)
slashing protector ignored duplicate attestation: ...
```

One such line after a restart or a reorg is normal. Repeated rejections for the same validator mean
that something else may be signing with the key. Stop and investigate.

Grandine keeps the records of the last 256 epochs (`--slashing-protection-history-limit`) and prunes
older ones once per epoch. The lowest epoch and slot still on record act as a low watermark, so
pruning never allows an older, conflicting message.

> **Note:** Keep Web3Signer's own slashing protection enabled as well. Grandine checks every message
> before it asks any signer, but a second, independent check costs little.

## Where the database lives

The database is an SQLite file named `slashing_protection.sqlite` in the validator directory:

```text
~/.grandine/<NETWORK>/validator/slashing_protection.sqlite
```

With `--data-dir /path/to/data`, it is `/path/to/data/<NETWORK>/validator/slashing_protection.sqlite`.
The network name is appended to the data directory, so mainnet and Hoodi never share a database.

Grandine opens the database in exclusive locking mode, as
[EIP-3076](https://eips.ethereum.org/EIPS/eip-3076) recommends. While Grandine runs, no other
process can open it. This includes the `grandine interchange` subcommand, so stop the client before
you import or export.

Older versions of Grandine kept the file in the `beacon` directory. On startup, Grandine moves it to
the validator directory. When a schema migration needs it, Grandine also writes a backup file named
`interchange-<TIMESTAMP>.json` into the validator directory before it changes the database.

> **Warning:** With `--in-memory`, the slashing protection database exists only in memory and is lost
> when the process exits. Never run real validators with `--in-memory`.

Each validator client keeps its own database. A [separate validator client](./validator_client.md)
(`grandine vc`) stores it in its own data directory. Never let two Grandine processes share a data
directory, and never run the same keys in two processes, even if each has protection: the two
databases do not know about each other.

## Exporting and importing (EIP-3076)

The [EIP-3076 interchange format](https://eips.ethereum.org/EIPS/eip-3076) is a JSON file that every
major consensus client can read and write. Use it to move validators between machines or clients.
Grandine reads and writes version 5 of the format.

### The `interchange` subcommand

```bash
grandine [OPTIONS] interchange export FILE
grandine [OPTIONS] interchange import FILE
```

Options such as `--network` and `--data-dir` must come **before** `interchange`. The subcommand
itself takes only the file path. This is the opposite of `bn` and `vc`, whose options come after the
command name.

Export the slashing protection data of a mainnet node:

```bash
grandine --network mainnet interchange export slashing_protection.json
```

Import a file into a Hoodi node with a custom data directory:

```bash
grandine --network hoodi --data-dir /var/lib/grandine interchange import slashing_protection.json
```

Use the same `--network` and `--data-dir` that the node or validator client runs with. Otherwise
Grandine reads or writes a different database. This applies to data from a separate `grandine vc`
too: pass the validator client's own `--data-dir`.

On export, Grandine logs the number of records for each validator. If nothing was exported, it warns:

```text
no records were exported. This may indicate an issue if active validators are present. Please verify your configuration settings.
```

That usually means the wrong `--network` or `--data-dir`. On import, it reports the totals:

```text
interchange file imported (imported records: 1234, failed records: 0)
```

An import is rejected as a whole if the file's `genesis_validators_root` does not belong to the
selected network, or if its format version is not 5. Within a valid file, Grandine imports every
record it can and counts the rest as failed. Duplicate public keys in the file are accepted.
Records that are already in the database cannot be stored twice, so importing the same file again
reports them as failed. That is harmless.

For predefined networks, the subcommand works offline. For a custom network, Grandine needs the
genesis state (for example from `--configuration-directory` or `--genesis-state-file`) to find the
genesis validators root.

### With Docker

The image's entry point is `grandine`, and it runs as root, so the data directory is
`/root/.grandine` inside the container. Stop the running container first, then:

```bash
docker run --rm                         \
  -v $HOME/.grandine:/root/.grandine    \
  sifrai/grandine:stable                \
  --network mainnet                     \
  interchange export /root/.grandine/slashing_protection.json
```

The file appears as `$HOME/.grandine/slashing_protection.json` on the host.

### Through the Keymanager API

The [Keymanager API](./keymanager_api.md) also carries interchange data. `DELETE /eth/v1/keystores`
returns the slashing protection data of the deleted keys, and `POST /eth/v1/keystores` accepts it in
the `slashing_protection` field. Use this when another tool moves keys between running clients.

## Moving validators safely

The rule is simple: the old client must stop signing before the new one starts, and the new one must
know what the old one signed.

1. Sync the new node first, so it is ready to take over.
2. Stop the old validator client, and make sure it cannot start again (disable its service, or
   remove its keys).
3. Export the slashing protection data from the old client.
4. Import the file into Grandine with `grandine ... interchange import FILE`.
5. Import the keys (see [Managing validator keys](./key_management.md)).
6. Wait until at least one or two full epochs have passed since the old client's last attestation.
   You can check this on a block explorer.
7. Start Grandine. Consider [doppelganger protection](./doppelganger_protection.md) as a final check.

Waiting is cheap: a few missed attestations cost far less than a slashing. See also
[Migrating from another client](./migration.md).

## If the database is lost

Without its database, Grandine has no memory of what the validators signed. It creates a new, empty
database and would sign anything that does not conflict with messages it signs from then on. If the
old messages are still recent, a new one may conflict with them.

What to do:

1. **Restore from a backup.** If you have a recent interchange export, or a copy of
   `slashing_protection.sqlite` taken while Grandine was stopped, restore it.
2. **Look for automatic backups.** Check the validator directory for `interchange-*.json` files
   written during a migration. They are older, but still raise the low watermark.
3. **If you have nothing, wait.** Keep the validators offline for at least two full epochs after
   their last attestation and proposal, as shown on a block explorer. New attestations then have
   higher source and target epochs than anything signed before, and new blocks are for later slots,
   so they cannot conflict. Enable doppelganger protection when you start again.

> **Tip:** Back up the slashing protection data regularly, and always before an upgrade or a move.
> Stop Grandine, then either run `interchange export` or copy `slashing_protection.sqlite`. A copy
> taken while Grandine runs may be inconsistent.

## Command line options

- `--slashing-protection-history-limit` (default: `256`): number of epochs of signing history to
  keep in the database.
- `--data-dir` (default: `$HOME/.grandine`): parent directory of the per-network data, including the
  validator directory that holds the database.
- `--network` (default: `mainnet`): selects the per-network directory and the genesis validators
  root that interchange files must match.
- `--in-memory` (default: disabled): keeps all data, including slashing protection, in memory only.

See the [command line reference](./cli_options.md) for the full list.
