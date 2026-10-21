# Subcommands and tools

Plain `grandine` runs a beacon node, with the integrated validator client when you give it
validator keys. Subcommands select a different mode or run a one-off tool and exit.

| Subcommand | What it does |
| --- | --- |
| `bn` | Run only the beacon node, without a validator client. |
| `vc` | Run only the validator client against one or more remote beacon nodes. |
| `interchange import` / `interchange export` | Import or export slashing protection data (EIP-3076). |
| `db-info` | Show information about the records in the beacon or sync database. |
| `db-stats` | Show the size of each kind of entry in the beacon database. |
| `export` | Export finalized blocks and states in a slot range as SSZ files, for debugging. |
| `replay` | Replay exported blocks and check the result against an exported state, for debugging. |
| `help` | Print help for Grandine or for a subcommand. |

Print the help of any subcommand with `--help`:

```bash
grandine --help
grandine vc --help
grandine interchange export --help
```

## Where options go

The rule differs between the run modes and the tools:

- **`bn` and `vc`** take all options after the subcommand. An option given before `bn` or `vc` is
  refused with an error such as `--network must be specified after vc`.

  ```bash
  grandine bn --network hoodi --http-port 5052          # correct
  grandine --network hoodi bn                            # refused
  ```

- **The tools** (`interchange`, `db-info`, `db-stats`, `export`, `replay`) take Grandine's own
  options, such as `--network` and `--data-dir`, **before** the subcommand, and the tool's own
  options after it.

  ```bash
  grandine --network hoodi --data-dir /var/lib/grandine interchange export slashing.json
  ```

The tools use the same data directory layout as a running node, so give them the same `--network`,
`--data-dir` and storage options that the node uses. They never connect to the network and do not
check whether the node's ports are free.

`--args-file` works with every mode. For `bn` and `vc` its options are applied after the
subcommand.

## `bn`: beacon node only

Runs the beacon node and refuses validator options such as `--keystore-dir`,
`--enable-validator-api` or `--report-validator-performance`. Use it for a node that serves one or
more separate validator clients, or that has no validators.

```bash
grandine bn \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --checkpoint-sync-url https://CHECKPOINT-HOST
```

See [Running a beacon node](./beacon_node.md).

## `vc`: validator client only

Runs the validator client against remote beacon nodes given with `--beacon-node-urls` (required).
It refuses options that only the built-in beacon node uses, such as `--checkpoint-sync-url`.

```bash
grandine vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --keystore-dir /path/to/keystores \
  --keystore-password-file /path/to/password.txt
```

> **Warning:** Never load the same validator keys in two places, for example in a `grandine` with
> keys and in a `grandine vc`. That gets the validator slashed. See
> [Validator client](./validator_client.md) and [Redundancy and fallback beacon nodes](./redundancy.md).

## `interchange`: slashing protection import and export

Reads or writes a slashing protection interchange file in the
[EIP-3076](https://eips.ethereum.org/EIPS/eip-3076) format. Use it when you move validators to or
from Grandine, or between machines.

```bash
# Export the slashing protection history
grandine --network mainnet interchange export slashing_protection.json

# Import a history exported from another client or machine
grandine --network mainnet interchange import slashing_protection.json
```

- `interchange export FILE_PATH` writes all records in the slashing protection database. It logs
  `exported N records for 0x...` for each validator, and warns `no records were exported` if the
  database is empty.
- `interchange import FILE_PATH` merges the file into the database and logs
  `interchange file imported (imported records: N, failed records: M)`.

The database is `{data-dir}/{network}/validator/slashing_protection.sqlite`, so
`$HOME/.grandine/mainnet/validator/slashing_protection.sqlite` by default. A separate
`grandine vc` uses the same location, so the same command works for it.

Stop Grandine before you import or export, so that the history cannot change in the meantime.
The interchange file is checked against the network's genesis validators root, which is built in
for the predefined networks. For a custom network, Grandine needs the genesis state.

`--slashing-protection-history-limit` (default `256` epochs), given before the subcommand, sets how
much history is kept when the database is opened.

With Docker, mount the data directory and write the file into it:

```bash
docker run --rm \
  -v $HOME/.grandine:/root/.grandine \
  sifrai/grandine:stable \
  --network mainnet interchange export /root/.grandine/slashing_protection.json
```

See [Slashing protection](./slashing_protection.md) and [Migrating from another client](./migration.md).

## `db-info`: database records

Prints information about the records in a beacon node database.

```bash
grandine --network hoodi db-info --database beacon
grandine --network hoodi db-info --database sync
```

Options:

- `-d`, `--database`: required. `beacon` for the `beacon_fork_choice` database or `sync` for the
  sync database.
- `-p`, `--path`: a custom directory that holds the database files. By default the database in the
  store directory is used.

```bash
grandine --network hoodi db-info -d sync -p ~/.grandine/hoodi/beacon/sync
```

## `db-stats`: database entry sizes

Prints the number of entries and the total key and value sizes of each kind of entry in the
`beacon_fork_choice` database: blocks, states, blob and data column sidecars, and the indexes. Use
it to see what takes up disk space. See [Storage and database](./storage.md).

```bash
grandine --network hoodi db-stats
grandine --network hoodi db-stats -p ~/.grandine/hoodi/beacon/beacon_fork_choice
```

Options:

- `-p`, `--path`: a custom directory that holds the `beacon_fork_choice` database files.

## `export`: dump blocks and states

Writes the states at the first and last slot of a range, and every finalized block in the range,
as SSZ files. This is a debugging tool, used with `replay` to reproduce state transitions.

```bash
grandine --network hoodi export --from 1000 --to 1010 --output-dir /tmp/grandine-export
```

Options:

- `-f`, `--from SLOT`: required. First slot, inclusive.
- `-t`, `--to SLOT`: required. Last slot, inclusive.
- `-o`, `--output-dir`: output directory. Default: the current directory.

Files are named `beacon_state_slot_SSSSSS_root_0x....ssz` and
`beacon_block_slot_SSSSSS_root_0x....ssz`. States that are not stored are computed from the
nearest stored state. Only finalized blocks are exported, and they must be stored with their
execution payloads: the node must run with `--store-payloads`, otherwise the export fails with
`block at slot N is stored blinded and cannot be exported`.

The `beacon_fork_choice` database is only read. `export`, `db-info` and `db-stats` can run while
Grandine is running: the database supports access from several processes at once. While Grandine is
writing, a subcommand may wait a moment before it starts.

## `replay`: replay exported blocks

Loads the exported state at `--from`, applies the exported blocks up to `--to`, and checks that the
result matches the exported state at `--to`. It fails if the states differ.

```bash
grandine --network hoodi replay --from 1000 --to 1010 --input-dir /tmp/grandine-export
```

Options:

- `-f`, `--from SLOT`: required. Start slot, inclusive. A state file for this slot must exist.
- `-t`, `--to SLOT`: required. End slot, inclusive. A state file for this slot must exist.
- `-i`, `--input-dir`: directory with the exported files. Default: the current directory.

## Command line options

The options of each tool are listed in its section. Grandine's general options are described in the
[Command line reference](./cli_options.md). The ones most often used with the tools:

- `--network`: default `mainnet`. The network whose data directory and configuration to use.
- `--data-dir`: default `$HOME/.grandine`. Parent directory of the per-network data directories.
- `--store-directory`: default `{data-dir}/{network}/beacon`. Where the beacon node databases live.
- `--slashing-protection-history-limit`: default `256`. Epochs of slashing protection history to keep.
