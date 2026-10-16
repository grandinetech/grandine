## Validator client

The Validator Client runs inside Grandine when validator keys are passed to it, or on its own against remote beacon nodes (see [Running the validator client separately](#running-the-validator-client-separately)). Let's try running Grandine with a new validator enabled on the Goerli network (assuming you already have keys, secrets etc.):

```
docker run                                                          \ 
  -p 9000:9000/tcp                                                  \
  -p 9000:9000/udp                                                  \
  -v $HOME/.grandine:/root/.grandine                                \
  -v $HOME/.grandine/jwtsecret:/root/.grandine/jwtsecret            \
  -v $HOME/.grandine/validator_keys:/root/.grandine/validator_keys  \
  -v $HOME/.grandine/secrets:/root/.grandine/secrets                \
  sifrai/grandine:unstable grandine                                 \
  --eth1-rpc-urls ETH1-RPC-URL                                      \
  --network goerli                                                  \
  --keystore-dir /root/.grandine/validator_keys                     \
  --keystore-password-file /root/.grandine/secrets
  --jwtsecret /root/.grandine/jwtsecret
```

In this example, the same secret is used to secure all the keystores, this secret should be placed in `$HOME/.grandine/secrets` file. Otherwise, for every keystore file in `$HOME/.grandine/validator_keys` there should be a corresponding file in the `$HOME/.grandine/secrets` directory with the secret file named the same as the corresponding keystore file except the extension should be `.txt` instead of `.json`.

For any sensitive keys it's a must to use a remote signer.

Discovered validators are recorded in [`validators.yml`](./validator_definitions.md), which also holds per-validator settings such as fee recipients and graffiti. Keystores from `--keystore-dir` are treated as read-only: the Keymanager API cannot delete them — remove the keystore file and its entry, or set `enabled: false` in `validators.yml`, instead.

### Relevant command line options:

* `--keystore-dir` - a directory containing validator keystore files; 
* `--keystore-password-file` - a file containing a single secret for all the validator keystore files (this option usable if all the keystores are secured with the same secret);
* `--keystore-password-dir` - a directory containing secrets for all the validator keystore files (this option usable if all the keystores are secured with not the same secret), for every keystore file in `--keystore-dir` there should be a corresponding file in the `--keystore-password-dir` directory with the secret file named the same as the corresponding keystore file except the extension should be `.txt` instead of `.json`.

### Running the validator client separately

Grandine can run in three ways:

* `grandine` - the beacon node, together with the built-in validator client if validator keys are passed;
* `grandine bn` - only the beacon node;
* `grandine vc` - only the validator client, which performs its duties through the Beacon Node API of one or more remote beacon nodes.

```
grandine vc                                                  \
  --network hoodi                                            \
  --beacon-node-urls http://node-1:5052,http://node-2:5052   \
  --keystore-dir /root/.grandine/validator_keys              \
  --keystore-password-file /root/.grandine/secrets
```

Options must be given after `bn` or `vc`; an option given before the command is refused. `vc` refuses options that only the built-in beacon node acts on (for example `--checkpoint-sync-url`, `--target-peers` or `--builder-url`), and `bn` refuses validator options (for example `--keystore-dir` or `--enable-validator-api`).

With `vc`, `--detect-doppelgangers` does not need `--track-liveness`: liveness is queried from the remote beacon nodes. With the built-in beacon node, `--detect-doppelgangers` still requires `--track-liveness`.

With `vc`, a validator without a fee recipient, given either with `--suggested-fee-recipient` or per validator in `validators.yml`, is not registered with the builder and gets no proposer preferences published, and the remote beacon node pays its own default fee recipient for local payloads. The built-in beacon node falls back to a default fee recipient instead.

### Relevant command line options for `vc`:

* `--beacon-node-urls` - a list of beacon node API URLs to perform validator duties against (required). Among the healthiest nodes, duties go to the one with the newest head, then to the first listed;
* `--publish-to-every-node` - a list of duties to publish to every beacon node rather than the first one (default: `all`). Possible values: `all`, `aggregates`, `attestations`, `blocks`, `payload-attestations`, `proposer-preferences`, `sync-committee-contributions`, `sync-committee-messages`. Given without a value, everything is published to the first node only;
* `--use-builder` - use the builder behind the beacon nodes: register validators with it and accept its payloads (default: disabled). Without it only local payloads are requested and builder boost factors are ignored. Relevant only until Gloas.
