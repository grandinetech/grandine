# Fee recipient, graffiti and gas limit

When one of your validators proposes a block, three settings shape it:

- the **fee recipient**: the execution-layer address that receives the priority fees (tips) of the
  block and any MEV payment;
- the **graffiti**: 32 bytes of free text stored in the block;
- the **gas limit**: the gas limit the validator asks for. Each block can move the network's gas
  limit a little toward the proposer's preference.

Each can be set once for all validators on the command line, and overridden per validator in
[`validators.yml`](./validator_definitions.md) or through the [Keymanager API](./keymanager_api.md).

## Fee recipient

> **Warning:** Always set a fee recipient that you control. If you set none, the integrated validator
> client sends your block rewards from fees to the Grandine team's donation address (see
> [Default behavior](#default-behavior-when-none-is-set)).

Set one address for all validators with `--suggested-fee-recipient`:

```bash
grandine                                   \
  --network mainnet                        \
  --jwt-secret /path/to/jwt.hex            \
  --eth1-rpc-urls http://EL-HOST:8551      \
  --keystore-dir /path/to/validator_keys   \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient 0xYOUR_EXECUTION_ADDRESS
```

With Docker, add the same option after the image name:

```bash
docker run                                       \
  -v $HOME/.grandine:/root/.grandine             \
  sifrai/grandine:stable                         \
  --network mainnet                              \
  --suggested-fee-recipient 0xYOUR_EXECUTION_ADDRESS \
  ...
```

The address must be a valid 20-byte execution address. Use an address whose private key you hold, or
a smart contract you have checked, such as a pool's fee distributor. It does not need to match the
withdrawal address.

At startup, Grandine logs the default it will use:

```text
suggested fee recipient: 0x...
```

Check this line after every configuration change.

### Per-validator fee recipients

Add `fee_recipient` to a validator's entry in `validators.yml`
(`~/.grandine/<NETWORK>/validator/validators.yml` by default):

```yaml
- enabled: true
  pubkey: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
  type: local_keystore
  keystore_path: /path/to/validator_keys/keystore-0.json
  keystore_password_path: /path/to/secrets/keystore-0.txt
  fee_recipient: "0x0000000000000000000000000000000000000001"
```

Edit the file only while Grandine is stopped, or use the Keymanager API, which changes it for you at
runtime.

### Fee recipient precedence

For a validator run by the integrated validator client, the first match wins:

1. `fee_recipient` in the validator's `validators.yml` entry (also what the Keymanager API sets);
2. `--suggested-fee-recipient`;
3. the Grandine donation address.

When a Grandine beacon node builds a block for a validator, it uses, in order:

1. the address a validator client sent through `POST /eth/v1/validator/prepare_beacon_proposer`
   (remote validator clients send this; the integrated one does not need to);
2. the `validators.yml` entry on the beacon node, if it has one for that validator;
3. the beacon node's `--suggested-fee-recipient`;
4. the Grandine donation address.

### Default behavior when none is set

- **Integrated validator client** (plain `grandine` with keys): Grandine falls back to its donation
  address, `0xe7cf7C3BA875Dd3884Ed6a9082d342cb4FBb1f1b`. This address is used for local blocks and
  sent to the builder in validator registrations. The startup line `suggested fee recipient` shows
  it.
- **Beacon node only** (`grandine bn`): when a remote validator client does not send a fee recipient
  for a validator, the beacon node uses its own `--suggested-fee-recipient`, or else the donation
  address. Set `--suggested-fee-recipient` on beacon nodes that serve other validator clients.
- **Separate validator client** (`grandine vc`): there is no fallback address. A validator without a
  fee recipient, either from `--suggested-fee-recipient` or from `validators.yml`, is not reported
  to the beacon nodes through `prepare_beacon_proposer`, is not registered with a builder, and gets
  no proposer preferences published (from Gloas on). The beacon node then pays its own default
  fee recipient for blocks it builds locally. See
  [Validator client](./validator_client.md).

## Graffiti

Set a default graffiti with `--graffiti`:

```bash
grandine ... --graffiti "my staking setup"
```

The text must fit in 32 bytes (UTF-8). A longer value is rejected at startup.

`--graffiti` can be given more than once. Grandine then rotates through the values, one per block
proposal:

```bash
grandine ... --graffiti "first" --graffiti "second" --graffiti "third"
```

Per-validator graffiti goes in `validators.yml`:

```yaml
- enabled: true
  pubkey: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
  type: local_keystore
  keystore_path: /path/to/validator_keys/keystore-0.json
  keystore_password_path: /path/to/secrets/keystore-0.txt
  graffiti: "validator zero"
```

Precedence: the `validators.yml` entry (or the Keymanager API), then `--graffiti`, then none.
Grandine validates the per-validator graffiti on startup and refuses to start if it is too long.

### Client fingerprint ("blockprint")

When a Grandine beacon node builds a block, it appends a short client fingerprint to the graffiti
if there is room. The fingerprint names the execution client and both clients' commits, followed by
`Grandine/<version>`. For example, the graffiti `test` with a Besu execution client may become:

```text
test BU4e2eGR6a37 Grandine/1.2.3
```

Parts that do not fit are left out, and your own text is never truncated. With no graffiti set, the
block carries only the fingerprint. This helps researchers measure client diversity. To turn it off,
start the beacon node with `--disable-blockprint-graffiti`. It is a beacon node option: with
`grandine vc`, the remote beacon node decides.

## Gas limit

By default, Grandine asks for the gas limit scheduled by the network configuration for the current
epoch, or 60,000,000 when no schedule applies. Change the default for all validators with
`--default-gas-limit`:

```bash
grandine ... --default-gas-limit 60000000
```

Per validator, set `gas_limit` in `validators.yml`:

```yaml
- enabled: true
  pubkey: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
  type: local_keystore
  keystore_path: /path/to/validator_keys/keystore-0.json
  keystore_password_path: /path/to/secrets/keystore-0.txt
  gas_limit: 60000000
```

Precedence: the `validators.yml` entry (or the Keymanager API), then `--default-gas-limit`, then the
scheduled limit, then 60,000,000.

The gas limit goes into builder registrations and, from the Gloas fork on, into the proposer
preferences that Grandine publishes. If a configured limit exceeds the scheduled one, Grandine warns
when it registers validators:

```text
3 validators configured gas limit exceeds the recommended gas limit of 60000000
```

> **Tip:** Change the gas limit only if you follow the community's coordination on it. Most
> operators should leave the default.

## Changing settings at runtime with the Keymanager API

The [Keymanager API](./keymanager_api.md) changes these settings without a restart. Grandine stores
the change in the validator's `validators.yml` entry, so it survives restarts. Enable the API with
`--enable-validator-api`. It listens on `127.0.0.1:5055` by default and requires the bearer token
stored in `api-token.txt` in the validator directory (or in `--validator-api-token-file`).

```bash
TOKEN=$(cat ~/.grandine/mainnet/validator/api-token.txt)
PUBKEY=0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a
```

Fee recipient:

```bash
# Read
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5055/eth/v1/validator/$PUBKEY/feerecipient

# Set
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"ethaddress": "0xYOUR_EXECUTION_ADDRESS"}' \
  http://127.0.0.1:5055/eth/v1/validator/$PUBKEY/feerecipient

# Remove the override (fall back to the default)
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5055/eth/v1/validator/$PUBKEY/feerecipient
```

Gas limit:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"gas_limit": "60000000"}' \
  http://127.0.0.1:5055/eth/v1/validator/$PUBKEY/gas_limit
```

Graffiti:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"graffiti": "my staking setup"}' \
  http://127.0.0.1:5055/eth/v1/validator/$PUBKEY/graffiti
```

`GET` and `DELETE` work the same way for `gas_limit` and `graffiti`. A successful `POST` returns
`202 Accepted`, and a `DELETE` returns `204 No Content`.

Notes:

- `GET .../feerecipient` returns the value that applies, including the default. With `grandine vc`
  and no fee recipient configured, it returns `404`.
- `GET .../gas_limit` returns the effective gas limit, including the scheduled default.
- A `POST` or `DELETE` for a validator without a `validators.yml` entry returns `404`. Validators
  loaded only from `--web3signer-urls` have no entry. See [Web3Signer](./web3signer.md) for how to
  give one an entry.

## Command line options

- `--suggested-fee-recipient` (default: none; the integrated validator client and `grandine bn` fall
  back to the Grandine donation address): default fee recipient for all validators.
- `--graffiti` (default: none): default block graffiti, up to 32 bytes. Repeat it to rotate values.
- `--disable-blockprint-graffiti` (default: disabled): beacon node option. Do not append the client
  fingerprint to the graffiti.
- `--default-gas-limit` (default: the scheduled gas limit, or `60000000`): default gas limit for all
  validators.
- `--enable-validator-api` (default: disabled): enables the Keymanager API used to change these
  settings at runtime.

See the [command line reference](./cli_options.md) for the full list.
