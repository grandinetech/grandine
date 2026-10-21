# Validator client

The validator client holds the validator keys and performs the validator's duties: it attests, proposes blocks, aggregates and takes part in sync committees. It gets its duties and the data to sign from a beacon node, signs with the keys (or asks a [Web3Signer](./web3signer.md) to sign), checks every signature against [slashing protection](./slashing_protection.md), and hands the result back to the beacon node to broadcast.

Grandine runs in one of three ways:

| Command | What runs |
|---|---|
| `grandine` | The beacon node, with the built-in validator client when validator keys are given |
| `grandine bn` | Only the beacon node, with no validator client |
| `grandine vc` | Only the validator client, against the Beacon Node API of one or more remote beacon nodes |

## The integrated validator client (default)

The default and simplest setup is a single `grandine` process with keys. The validator client then runs inside the beacon node and reads duties straight from its fork choice, with no HTTP round trips in between. There is one process to run, monitor and update, and one data directory.

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

With Docker (the image's entrypoint is `grandine`):

```bash
docker run -d --name grandine \
  --network host \
  -v $HOME/.grandine:/root/.grandine \
  -v /path/to/jwt.hex:/jwt.hex:ro \
  -v /path/to/validator_keys:/validator_keys:ro \
  -v /path/to/password.txt:/password.txt:ro \
  sifrai/grandine:stable \
  --network hoodi \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /jwt.hex \
  --keystore-dir /validator_keys \
  --keystore-password-file /password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

Validators need an execution client: Grandine refuses to start with keys but without `--eth1-rpc-urls`.

Keys can come from a keystore directory, the [Keymanager API](./keymanager_api.md) or a [Web3Signer](./web3signer.md). See [Managing validator keys](./key_management.md). Whatever the source, Grandine records the validators it manages in [`validators.yml`](./validator_definitions.md), which also holds per-validator settings such as fee recipients and graffiti.

Without a fee recipient, either `--suggested-fee-recipient` or a per-validator one, the integrated validator client pays the execution rewards of its blocks to the Grandine donation address. See [Fee recipient, graffiti and gas limit](./fee_recipient.md).

## The separate validator client (`grandine vc`)

`grandine vc` runs the validator client on its own. It talks to beacon nodes only through the standard Beacon Node API, given with `--beacon-node-urls`. Use it when:

- the validator keys must live on a different machine from the beacon node, for example a hardened signing host;
- one validator client should use several beacon nodes, so that it keeps working when one of them is down or behind (see [Redundancy and fallback beacon nodes](./redundancy.md));
- you want to restart or update the beacon node and the validator client independently.

The cost is an extra process to manage and HTTP latency between the two. If none of the points above applies, stay with the integrated validator client.

> **Warning:** Never run the same validator keys in two places at once. That includes the integrated validator client and `grandine vc`, two `grandine vc` processes, or Grandine and another client. Two signers with the same key eventually sign conflicting messages, and the validator is slashed. Slashing protection cannot prevent this, because each process only knows its own database.

> **Warning:** Give each validator client its own data directory, and never point two validator clients at the same one. The validator directory holds the slashing protection database, `validators.yml` and the keys imported through the API.

### Running the beacon node and the validator client separately

Start the beacon node with `grandine bn`. If the validator client runs on another host, bind the Beacon Node API to an address that host can reach, and firewall it so that only the validator client can connect:

```bash
grandine bn \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --http-address 0.0.0.0 \
  --http-port 5052
```

Then start the validator client with the keys:

```bash
grandine vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

With Docker:

```bash
docker run -d --name grandine-vc \
  --network host \
  -v $HOME/.grandine-vc:/root/.grandine \
  -v /path/to/validator_keys:/validator_keys:ro \
  -v /path/to/password.txt:/password.txt:ro \
  sifrai/grandine:stable \
  vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --keystore-dir /validator_keys \
  --keystore-password-file /password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

A separate validator client does not need an execution client, a JWT secret or P2P ports. Each beacon node it uses needs its own execution client.

### Rules for options

- Options go after `bn` or `vc`. An option before the command is refused, for example `grandine --network hoodi vc ...` fails with `--network must be specified after vc`.
- `vc` refuses options that only the built-in beacon node acts on, for example `--eth1-rpc-urls`, `--checkpoint-sync-url`, `--target-peers`, `--http-port`, `--builder-url` or `--track-liveness`.
- `bn` refuses validator options, for example `--keystore-dir`, `--enable-validator-api`, `--beacon-node-urls` or `--report-validator-performance`.
- `--args-file` works with both: the options in the file are applied to the command they follow.
- `--report-validator-performance` reads blocks from the built-in beacon node, so `vc` refuses it.

### How `vc` checks its beacon nodes

At startup, the validator client asks every beacon node for its genesis. All nodes that answer must report the same genesis validators root, and for a predefined network it must match that network. A node on a different network or chain stops the validator client with an error, because restarting would not fix it. If no node answers, it retries every 2 seconds:

```text
no beacon node given with --beacon-node-urls reported genesis; retrying in 2 s
genesis agreed with the beacon nodes given with --beacon-node-urls (genesis validators root: 0x..., genesis time: ...)
checking remote beacon nodes
1 of 1 remote beacon nodes are ready to serve duties
```

After that, the validator client polls each node's health once per slot and follows each node's head through the event stream. How it picks a node for each duty is described in [Redundancy and fallback beacon nodes](./redundancy.md).

### Behavior that differs from the integrated validator client

- **Fee recipient.** A validator without a fee recipient, given with `--suggested-fee-recipient` or per validator in `validators.yml`, is not prepared as a proposer on the beacon nodes, is not registered with the builder, and gets no proposer preferences published. The beacon node then pays its own default fee recipient for local payloads. The integrated validator client falls back to the Grandine donation address instead.
- **Builder.** `--builder-url` belongs to the beacon node. On the validator client, `--use-builder` registers the validators with the builder behind the beacon nodes and accepts builder payloads. Without it only local payloads are requested and builder boost factors are ignored. It matters only until the Gloas fork, after which builders bid over gossip and need no registration. See [Builder API and MEV](./builder_api_and_mev.md).
- **Doppelganger protection.** `--detect-doppelgangers` does not need `--track-liveness` on `vc`, because liveness is asked from the beacon nodes. A Grandine beacon node only answers liveness requests when it runs with `--track-liveness`, so start such nodes with it. With the integrated validator client, `--detect-doppelgangers` still requires `--track-liveness`. See [Doppelganger protection](./doppelganger_protection.md).
- **Metrics.** With `--metrics`, a separate validator client exposes only validator client metrics. If it runs on the same host as a beacon node that also has metrics on, give one of them another `--metrics-port` (default `5054`). See [Metrics](./metrics.md).
- **Graffiti.** `--disable-blockprint-graffiti` is a beacon node option. On `vc`, set the graffiti with `--graffiti` or per validator.

## Moving keys from the integrated validator client to `grandine vc`

The keys, `validators.yml` and the slashing protection database all live in the validator directory, `<data-dir>/<network>/validator` (by default `~/.grandine/<network>/validator`). Keystores imported through the Keymanager API store their passwords in `<data-dir>/<network>/secrets`. Moving to a separate validator client means moving these, and making sure the old process no longer signs.

> **Warning:** Stop the old process first, confirm that it has stopped, and only then start the new one. Never have both running with the keys, not even for a moment. If you run a service manager, disable the old service so that it cannot restart.

1. **Stop Grandine** and make sure it does not restart:

   ```bash
   sudo systemctl stop grandine
   sudo systemctl disable grandine
   ```

2. **Back up the slashing protection data** in the standard interchange format. Use the old data directory:

   ```bash
   grandine --network mainnet --data-dir /path/to/old-data-dir interchange export /path/to/slashing-protection.json
   ```

3. **Move the validator directory** to the validator client's data directory. Moving rather than copying makes sure only one copy is in use:

   ```bash
   mkdir -p /path/to/vc-data-dir/mainnet
   mv /path/to/old-data-dir/mainnet/validator /path/to/vc-data-dir/mainnet/
   mv /path/to/old-data-dir/mainnet/secrets /path/to/vc-data-dir/mainnet/   # only if it exists
   ```

   `validators.yml` stores absolute paths. Update the paths of keys imported through the API so that they point to the new location:

   ```bash
   sed -i 's#/path/to/old-data-dir/mainnet/#/path/to/vc-data-dir/mainnet/#g' \
     /path/to/vc-data-dir/mainnet/validator/validators.yml
   ```

   Keystores loaded from `--keystore-dir` keep their own paths. If the keystore directory moves too, update those paths, or remove their entries and let Grandine discover the keystores again.

4. **Restart the node without keys**, as `grandine bn` with the same beacon node options as before, minus the validator options. Add `--track-liveness`, because the doppelganger protection in step 5 asks the node for liveness. Without it, the validator client never starts performing duties. Make sure the validator client can reach its Beacon Node API.

5. **Start the validator client** with the new data directory and the same key options as before. Enabling doppelganger protection for the first start adds a safety check:

   ```bash
   grandine vc \
     --network mainnet \
     --data-dir /path/to/vc-data-dir \
     --beacon-node-urls http://BN-HOST:5052 \
     --keystore-dir /path/to/validator_keys \
     --keystore-password-file /path/to/password.txt \
     --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS \
     --detect-doppelgangers
   ```

6. **Check the logs** for the loaded keys and for `remote beacon nodes are ready to serve duties`, and watch the validators attest in the next epochs.

If you cannot move the directory, for example because the validator client runs on a new machine, copy only what you need. Import the interchange file into the new data directory before the first start:

```bash
grandine --network mainnet --data-dir /path/to/vc-data-dir interchange import /path/to/slashing-protection.json
```

Then load the keys there with `--keystore-dir` or the [Keymanager API](./keymanager_api.md), and delete them from the old machine.

To go back to the integrated validator client, follow the same steps in the other direction: stop `grandine vc`, move the validator directory back, and start `grandine` with the key options.

## Troubleshooting

- **`--NAME must be specified after vc`**: the option is placed before the command. Move it after `vc` or `bn`.
- **`beacon node at URL is on a different network`**: `--network` (or the custom configuration) does not match the beacon node. Fix the network or the URL.
- **`no remote beacon node is fully synced`**: every node is syncing, optimistic, has its execution client offline, or has a head more than `--max-empty-slots` slots behind. Duties are still attempted, but may fail or be late. Check the beacon nodes.
- **`no remote beacon node can serve duties`**: no node could be reached. Check the URLs, firewalls and that the nodes' HTTP API is enabled on a reachable address.
- **`--track-liveness must be specified for --detect-doppelgangers with the built-in beacon node`**: add `--track-liveness`, or run the validator client separately.

## Command line options

Options for keys, the Keymanager API and Web3Signer are listed on their own pages: [Managing validator keys](./key_management.md), [Keymanager API](./keymanager_api.md) and [Web3Signer](./web3signer.md).

Options for `grandine vc` only:

- `--beacon-node-urls` (required): comma-separated Beacon Node API URLs to perform duties against.
- `--publish-to-every-node` (default `all`): duties to publish to every beacon node rather than only the first one that accepts them. See [Redundancy and fallback beacon nodes](./redundancy.md).
- `--use-builder` (disabled): register validators with the builder behind the beacon nodes and accept its payloads (until Gloas).

Validator options for both `grandine` and `grandine vc`:

- `--detect-doppelgangers` (disabled): enable doppelganger protection.
- `--report-validator-performance` (disabled): log validator performance reports; integrated validator client only.
- `--slashing-protection-history-limit` (default `256`): number of epochs of slashing protection data to keep.
- `--suggested-fee-recipient` (no default): default fee recipient for all validators.
- `--graffiti` (no default): default block graffiti.
- `--default-gas-limit` (default: the scheduled gas limit, or 60000000): default execution gas limit.
- `--default-builder-boost-factor` (default `100`): the percentage by which a builder's bid is scaled before Grandine weighs it against the local payload.
- `--max-empty-slots` (default `32`): how many slots a head may fall behind before it is considered stale.
- `--data-dir` (default `~/.grandine`): parent directory for the data files, which go to `<data-dir>/<network>`.

See [Command line reference](./cli_options.md) for the full list.
