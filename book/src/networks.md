# Supported networks

Grandine has built-in configurations for Ethereum Mainnet and the public testnets. Select one with
`--network`. Other networks, such as devnets and private networks, are loaded from a configuration
directory with `--network custom`.

## Built-in networks

| Network | `--network` | Execution chain ID | Purpose |
| --- | --- | --- | --- |
| Mainnet | `mainnet` (default) | 1 | The real Ethereum network |
| Hoodi | `hoodi` | 560048 | The testnet for validators and staking infrastructure |
| Sepolia | `sepolia` | 11155111 | The testnet for application and smart contract developers |

For each built-in network, Grandine includes the chain configuration (fork schedule, deposit contract,
blob limits) and the bootnodes it uses to find its first peers. You only need to set `--network`.

```bash
grandine --network hoodi --eth1-rpc-urls http://127.0.0.1:8551 --jwt-secret /path/to/jwt.hex
```

The execution client must run on the same network as Grandine. A pair on different networks cannot
sync.

Each network has its own data directory, so you can keep data for several networks side by side:
`~/.grandine/mainnet`, `~/.grandine/hoodi` and so on. With `--data-dir /path/to/data`, the network name
is still appended: `/path/to/data/hoodi`.

### Mainnet

Mainnet is the default. Its genesis state is built into Grandine, so a start from genesis needs no
download, but syncing all of Mainnet from genesis takes a long time. Use
[checkpoint sync](./checkpoint_sync.md) instead.

Make deposits for Mainnet validators only through the official
[Staking Launchpad](https://launchpad.ethereum.org/).

### Hoodi

Hoodi is the testnet to use when you learn to run validators, test an upgrade or try a new setup
before Mainnet. Its fork schedule runs ahead of Mainnet, so new forks reach Hoodi first.

- Staking Launchpad: <https://hoodi.launchpad.ethereum.org/>
- Testnet ether: Hoodi faucets give out small amounts of test ether. Search for a current "Hoodi
  faucet"; they change often.

### Sepolia

Sepolia is meant for application developers. Its validator set is permissioned, so you can run a
Sepolia beacon node, but you cannot become a Sepolia validator with a normal deposit. Use Hoodi to
practice staking.

### Holesky

Holesky has reached its end of life. Fusaka activated on it on 1 October 2025, its maintainers
shut down most of its validators two weeks after the upgrade finalized, and client, testing and
infrastructure teams no longer support it (see the
[announcement](https://blog.ethereum.org/2025/09/01/holesky-shutdown-announcement)).
Grandine still accepts `--network holesky`, but do not use it: run validators on Hoodi, and use
Sepolia for application testing.

### Genesis state on testnets

On the first start on Sepolia, Holesky or Hoodi, Grandine downloads the network's genesis state from
the network's repository on GitHub and saves it as `genesis_state.ssz` in the beacon data directory
(for example `~/.grandine/hoodi/beacon/genesis_state.ssz`). This happens even with checkpoint sync,
because Grandine uses it to identify the chain. Later starts load the saved file.

If the machine cannot reach GitHub, either download the genesis state another way and pass it with
`--genesis-state-file`, or give another source with `--genesis-state-download-url`. Grandine checks
the genesis validators root of a downloaded or saved state against the known value for the network
and refuses a wrong file. It does not check a file given with `--genesis-state-file`.

### Checkpoint sync endpoints

Checkpoint sync needs a trusted beacon node on the same network. Public endpoints for Mainnet and the testnets are collected at
[eth-clients.github.io/checkpoint-sync-endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/). Your own beacon node, or one run by someone you trust, is better still.
See [Checkpoint sync](./checkpoint_sync.md).

## Custom networks and devnets

For a network that is not built in, use `--network custom` and point Grandine at a directory with the
network's files:

```bash
grandine \
  --network custom \
  --configuration-directory /path/to/network-config \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

The directory uses the layout that most devnets and testnets publish:

| File | Content | Override |
| --- | --- | --- |
| `config.yaml` | Chain configuration (fork epochs, deposit contract, timing) | `--configuration-file` |
| `genesis.ssz` | Genesis state in SSZ format | `--genesis-state-file` |
| `deposit_contract_block.txt` | Execution block number of the deposit contract deployment | `--deposit-contract-starting-block` |
| `bootstrap_nodes.txt` | Bootnode ENRs, one per line; `#` starts a comment | `--boot-nodes` |

Each file must exist unless you pass the matching option.
When you pass an option and the directory also has the file, the option wins and Grandine logs a
warning.

Notes:

- The data directory is named after `CONFIG_NAME` in `config.yaml`, for example
  `~/.grandine/my-devnet`. The name may contain only lowercase letters, digits and `-`.
- Grandine warns about unknown variables in `config.yaml` and ignores them.
- A custom network without `--eth1-rpc-urls` needs a genesis state file.
- `--network custom` without a configuration file stops with
  `--configuration-file must be specified when connecting to custom network`.
- Networks that use the `minimal` preset, common in local test setups, need a binary built with
  `make minimal`. See [Building from source](./build_from_source.md).

See [Configuration files and custom networks](./configuration_files.md) for the formats and for
checking a configuration with the `--verify-*` options.

## Command line options

- `--network`: default `mainnet`. One of `mainnet`, `sepolia`, `holesky`, `hoodi` or `custom`.
- `--configuration-directory`: no default. Directory with `config.yaml`, `genesis.ssz`, `deposit_contract_block.txt` and `bootstrap_nodes.txt`.
- `--configuration-file`: no default. Chain configuration YAML file; takes precedence over the directory.
- `--genesis-state-file`: no default. Genesis state SSZ file.
- `--genesis-state-download-url`: no default. URL to download the genesis state from.
- `--deposit-contract-starting-block`: no default. Execution block to start tracking the deposit contract from.
- `--boot-nodes`: no default. Comma-separated bootnode ENRs; replaces the built-in or file list.
- `--data-dir`: default `$HOME/.grandine`. Parent directory for data; the network name is appended.

See the [Command line reference](./cli_options.md) for the full list.
