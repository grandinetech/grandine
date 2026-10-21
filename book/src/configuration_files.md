# Configuration files and custom networks

Grandine reads two kinds of configuration files:

- **Chain configuration** describes a network: fork epochs, fork versions, genesis settings, and so
  on. Predefined networks have it built in. You supply it for a custom network or devnet.
- **An options file** (`--args-file`) holds Grandine's own command line options in YAML, so you do
  not have to put them all on the command line.

## Predefined networks

For `mainnet`, `sepolia`, `holesky` and `hoodi` you need no configuration files. Select the network
with `--network`:

```bash
grandine --network hoodi --eth1-rpc-urls http://EL-HOST:8551 --jwt-secret /path/to/jwt.hex
```

The chain configuration, boot nodes and deposit contract data are built into the binary. The mainnet
genesis state is built in too. For Sepolia, Holesky and Hoodi, Grandine downloads the genesis state
from the network's `eth-clients` repository on first start and saves it as
`beacon/genesis_state.ssz` in the data directory. Use `--genesis-state-download-url URL` to download
it from somewhere else, and `--checkpoint-sync-url` to skip syncing from genesis altogether. See
[Supported networks](./networks.md) and [Checkpoint sync](./checkpoint_sync.md).

## Custom networks

To join a network that Grandine does not know, use `--network custom` and point Grandine to the
network's configuration.

### With a configuration directory

Most testnets and devnets publish their configuration as a directory in the standard layout used by
the `eth-clients` repositories. Pass it with `--configuration-directory`:

```bash
grandine \
  --network custom \
  --configuration-directory /path/to/network-config \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex
```

Grandine reads these files from the directory:

| File | Contents | Required | Overridden by |
|---|---|---|---|
| `config.yaml` | Chain configuration (`CONFIG_NAME`, `PRESET_BASE`, fork epochs and versions, ...) | Yes | `--configuration-file` |
| `genesis.ssz` | Genesis state in SSZ | Yes, when Grandine needs the genesis state | `--genesis-state-file` |
| `deposit_contract_block.txt` | Execution block number the deposit contract was deployed in | Yes, for a beacon node | `--deposit-contract-starting-block` |
| `bootstrap_nodes.txt` | Boot node ENRs, one per line | Yes, for a beacon node | `--boot-nodes` |

Notes:

- In `bootstrap_nodes.txt`, empty lines are skipped and everything after `#` on a line is a comment.
  Grandine reads only the `.txt` file, not `bootstrap_nodes.yaml`.
- If an option overrides a file, Grandine logs a warning such as
  `both --configuration-directory and --boot-nodes specified; --boot-nodes will take precedence`.
- A separate validator client (`grandine vc`) reads `config.yaml` and `genesis.ssz` (to check that
  the beacon nodes are on the expected chain), but not the deposit block or boot node files.

### With individual files

You can also give the files one by one:

```bash
grandine \
  --network custom \
  --configuration-file /path/to/config.yaml \
  --genesis-state-file /path/to/genesis.ssz \
  --deposit-contract-starting-block 0 \
  --boot-nodes ENR1,ENR2 \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex
```

Rules Grandine enforces:

- `--network custom` needs a chain configuration. Without one, it stops with
  `--configuration-file must be specified when connecting to custom network`.
- A custom network needs either a genesis state or an execution client (from which Grandine waits for
  genesis by tracking deposits). Without both, it stops with
  `--eth1-rpc-urls must be specified when connecting to custom network without --genesis-state-file`.

### The chain configuration file

`config.yaml` uses the format of the consensus specifications' configuration files. A few fields
matter to Grandine in particular:

- `CONFIG_NAME` names the network. Grandine uses it as the name of the per-network data directory
  (`DATA_DIR/CONFIG_NAME`), so two custom networks with the same name share a data directory. It may
  contain only lowercase letters, digits and `-`. If it is missing, the name is `default`.
- `PRESET_BASE` selects the preset: `mainnet` or `minimal`. Release binaries include only the
  `mainnet` preset. A `minimal` network needs a binary built with `make minimal` (see
  [Building from source](./build_from_source.md)). Otherwise Grandine stops with
  `minimal preset is not included in this executable`.
- Variables Grandine does not know are ignored with a warning:
  `unknown configuration variables: [...]`. This is normal when a devnet adds fields for a future
  fork, but check the list if the node does not follow the chain.

### Verifying presets and configuration

The `--verify-*` options compare what Grandine loaded with a file you supply, and stop with a list of
differences if they do not match. They are useful to check that a devnet uses the same preset values
that Grandine was built with:

```bash
grandine \
  --network custom \
  --configuration-directory /path/to/network-config \
  --verify-configuration-file /path/to/network-config/config.yaml \
  --verify-electra-preset-file /path/to/presets/mainnet/electra.yaml \
  --verify-fulu-preset-file /path/to/presets/mainnet/fulu.yaml \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex
```

| Option | Compares |
|---|---|
| `--verify-phase0-preset-file` | Phase 0 preset variables |
| `--verify-altair-preset-file` | Altair preset variables |
| `--verify-bellatrix-preset-file` | Bellatrix preset variables |
| `--verify-capella-preset-file` | Capella preset variables |
| `--verify-deneb-preset-file` | Deneb preset variables |
| `--verify-electra-preset-file` | Electra preset variables |
| `--verify-fulu-preset-file` | Fulu preset variables |
| `--verify-configuration-file` | The whole chain configuration |

Variables missing from the file you verify against are filled in with their default values before the
comparison. A mismatch stops Grandine with an error in this form, listing every differing variable:

```text
PHASE variables in PRESET preset do not match file ("VARIABLE": expected VALUE_IN_FILE but found LOADED_VALUE, ...)
variables in configuration do not match file ("VARIABLE": expected VALUE_IN_FILE but found LOADED_VALUE, ...)
```

When `--verify-configuration-file` matches, Grandine logs
`configuration matches the one in configuration file`.

### Overriding configuration values

These options change single values after the configuration is loaded and verified. They are rarely
needed outside of testing:

| Option | Overrides |
|---|---|
| `--terminal-total-difficulty-override <DIFFICULTY>` | `TERMINAL_TOTAL_DIFFICULTY` |
| `--terminal-block-hash-override <BLOCK_HASH>` | `TERMINAL_BLOCK_HASH` |
| `--terminal-block-hash-activation-epoch-override <EPOCH>` | `TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH` |
| `--deposit-contract-starting-block <BLOCK_NUMBER>` | The deposit contract block |
| `--boot-nodes <ENRS>` | The boot node list |
| `--genesis-state-file <SSZ_FILE>` | The genesis state |

## Devnets

### Joining a published devnet

1. Download the devnet's configuration directory (it contains `config.yaml`, `genesis.ssz`,
   `deposit_contract_block.txt` and `bootstrap_nodes.txt`).
2. Start the devnet's execution client with the same JWT secret.
3. Start Grandine with the directory. Checkpoint sync from a devnet beacon node is the fastest way in:

```bash
grandine \
  --network custom \
  --configuration-directory /path/to/devnet-config \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex
```

### Local devnets with Kurtosis

[Kurtosis](https://github.com/ethpandaops/ethereum-package) can start a local multi-client network.
Grandine is one of its consensus clients, `cl_type: grandine`. The package uses
`sifrai/grandine:stable` by default (`ethpandaops/grandine:develop-minimal` with the minimal
preset); `cl_image` picks another image:

```yaml
# network_params.yaml
participants:
  - el_type: geth
    cl_type: grandine
    cl_image: sifrai/grandine:unstable
    count: 2
```

```bash
kurtosis run github.com/ethpandaops/ethereum-package --args-file network_params.yaml
```

Kurtosis generates the network configuration and passes it to Grandine for you. If you attach a
Grandine node that you run by hand to a local network like this, give it the generated configuration
directory with `--configuration-directory`, and add `--enable-private-discovery` so that discovery
accepts peers with private IP addresses.

## Keeping command line options in a file

`--args-file YAML_FILE` loads Grandine's own command line options from a YAML file. Grandine has no
TOML configuration; this YAML file is the only options file it reads.

### Format

The file is a flat mapping. Keys are long option names without the leading `--`. Underscores are
accepted in place of dashes (`http_port` is the same as `http-port`).

```yaml
# /etc/grandine/hoodi.yaml
network: hoodi
eth1-rpc-urls:
  - http://127.0.0.1:8551
jwt-secret: /etc/grandine/jwt.hex
checkpoint-sync-url: https://CHECKPOINT-HOST
data-dir: /var/lib/grandine
graffiti:
  - "my-node"
suggested-fee-recipient: "0xFEE_RECIPIENT_ADDRESS"
http-port: 5052
metrics: true
metrics-port: 5054
```

| YAML value | Becomes |
|---|---|
| `true` | The flag, for example `metrics: true` gives `--metrics` |
| `false` | Nothing (the flag is not given) |
| A number or a string | `--key value` |
| A list | The flag repeated for each item: `--key item1 --key item2` |
| `null`, a mapping, or a tagged value | An error: `config option ... has an unsupported value` |

For options that take a comma-separated list (such as `boot-nodes` or `trusted-peers`), a single
string with commas works too.

### Precedence

Options on the command line always win. If you set an option both in the file and on the command
line, the file's value is dropped, and this is true for lists as well: a list on the command line
replaces the file's list instead of adding to it. `requires` and `conflicts` rules are checked on the
combined set, so a requirement can be met by the file and the command line together.

```bash
# The file sets http-port: 5052; this run uses 6052
grandine --args-file /etc/grandine/hoodi.yaml --http-port 6052
```

### Where to put `--args-file`

- For plain `grandine` and the tool subcommands, put `--args-file` before the subcommand:
  `grandine --args-file FILE` or `grandine --args-file FILE export --from 0 --to 5`.
- For `bn` and `vc`, put it after the mode name, like every other option. The file then holds options
  for that mode:

```bash
grandine bn --args-file /etc/grandine/bn.yaml
grandine vc --args-file /etc/grandine/vc.yaml
```

```yaml
# /etc/grandine/vc.yaml
network: hoodi
beacon-node-urls: http://BN-HOST-1:5052,http://BN-HOST-2:5052
keystore-dir: /var/lib/grandine/keys
keystore-password-file: /var/lib/grandine/password.txt
suggested-fee-recipient: "0xFEE_RECIPIENT_ADDRESS"
```

Unknown keys are passed to the argument parser, which rejects them just as it would a mistyped
option on the command line.

## Keeping options in a service definition

Instead of an options file you can keep the flags in your service manager's configuration. See
[Running as a service](./running_as_a_service.md) for complete setups.

A systemd unit:

```ini
# /etc/systemd/system/grandine.service
[Service]
User=grandine
ExecStart=/usr/local/bin/grandine \
  --network mainnet \
  --data-dir /var/lib/grandine \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /etc/grandine/jwt.hex \
  --checkpoint-sync-url https://CHECKPOINT-HOST
Restart=always
```

Or, to keep the unit short, reference an options file:

```ini
ExecStart=/usr/local/bin/grandine --args-file /etc/grandine/mainnet.yaml
```

A Docker Compose service, where `command` holds the flags (the image's entrypoint is `grandine`):

```yaml
services:
  grandine:
    image: sifrai/grandine:stable
    restart: unless-stopped
    ports:
      - "9000:9000/tcp"
      - "9000:9000/udp"
      - "9001:9001/udp"
    volumes:
      - ./grandine-data:/root/.grandine
      - ./jwt.hex:/jwt.hex:ro
      - ./grandine.yaml:/grandine.yaml:ro
    command:
      - --args-file=/grandine.yaml
      - --http-address=0.0.0.0
```

## Command line options

- `--network` (default `mainnet`): network to connect to (`mainnet`, `sepolia`, `holesky`, `hoodi`, `custom`).
- `--configuration-directory` (default none): directory with `config.yaml`, `genesis.ssz`, `deposit_contract_block.txt` and `bootstrap_nodes.txt`.
- `--configuration-file` (default none): chain configuration file.
- `--genesis-state-file` (default none): genesis state in SSZ.
- `--genesis-state-download-url` (default built-in): where to download a predefined network's genesis state.
- `--deposit-contract-starting-block` (default from the network): deposit contract block.
- `--boot-nodes` (default from the network): boot node ENRs.
- `--verify-*-preset-file`, `--verify-configuration-file` (default none): check loaded values against a file.
- `--terminal-total-difficulty-override`, `--terminal-block-hash-override`, `--terminal-block-hash-activation-epoch-override` (default none): override single configuration values.
- `--enable-private-discovery` (default disabled): discover peers with private IP addresses.
- `--args-file` (default none): load command line options from a YAML file.

See the [Command line reference](./cli_options.md) for all options.
