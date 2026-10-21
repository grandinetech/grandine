# Keymanager API

The Keymanager API lets you manage a running validator client over HTTP: list, import and delete keys, manage remote signer keys, set per-validator fee recipients, gas limits and graffiti, and sign voluntary exits. Grandine implements the standard [Keymanager API](https://ethereum.github.io/keymanager-APIs/), so tools written for it, such as staking dashboards, work with Grandine too.

Grandine calls this server the validator API. It is separate from the [Beacon Node API](./beacon_node_api.md): it has its own address, port and authentication token, and it runs wherever the validator client runs, in `grandine` with keys or in `grandine vc`. `grandine bn` has no validator client and refuses `--enable-validator-api`.

## Enabling the API

The API is off by default. Turn it on with `--enable-validator-api`:

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --enable-validator-api
```

Or on a separate validator client:

```bash
grandine vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --enable-validator-api
```

A validator client can start with no keys at all and get every key through the API.

By default the API listens on `127.0.0.1:5055`. On startup Grandine logs where it listens and where the token is:

```text
Validator API is listening on 127.0.0.1:5055, authorization token file: /home/user/.grandine/hoodi/validator/api-token.txt
```

With Docker, publish the port only on the loopback interface of the host, or keep it unpublished and use the API from inside the container's network:

```bash
docker run -d --name grandine-vc \
  -p 127.0.0.1:5055:5055 \
  -v $HOME/.grandine-vc:/root/.grandine \
  sifrai/grandine:stable \
  vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --enable-validator-api \
  --validator-api-address 0.0.0.0
```

Inside the container the token file is `/root/.grandine/hoodi/validator/api-token.txt`, which is `$HOME/.grandine-vc/hoodi/validator/api-token.txt` on the host.

## Authentication

Every request must carry the API token as a bearer token:

```text
Authorization: Bearer YOUR-API-TOKEN
```

A request without the header or with a wrong token fails with `401` or `400`.

### Where the token comes from

- **By default**, the token file is `api-token.txt` in the validator directory: `<data-dir>/<network>/validator/api-token.txt`, or `~/.grandine/<network>/validator/api-token.txt`. If the file does not exist or cannot be read as a token, Grandine generates a random 256-bit token, writes it there as hex, and uses it. The token stays the same across restarts.
- **With `--validator-api-token-file`**, Grandine reads the token from that file and never writes it. If the file is missing or invalid, Grandine does not start.

A token file you provide must contain an even number of hex digits, at least 32 of them, and nothing else. A trailing newline makes the file invalid. Clients must send the token in lowercase. To create one:

```bash
openssl rand -hex 32 | tr -d '\n' > /path/to/api-token.txt
chmod 600 /path/to/api-token.txt
```

> **Warning:** The token gives full control over the keys: whoever holds it can delete keystores, import keys and sign exits. Keep the token file readable only by the Grandine user and the tools that need it. Grandine writes the default file with the default file permissions of its user, so restrict them with `chmod 600`.

## Exposing the API safely

Keep the API on `127.0.0.1` unless you have a reason not to. To use it from another machine, prefer an SSH tunnel to opening the port:

```bash
ssh -N -L 5055:127.0.0.1:5055 user@VC-HOST
```

If you do bind it to another interface with `--validator-api-address`, firewall the port so that only trusted hosts reach it. The API serves plain HTTP, so put it behind a TLS-terminating proxy if it must cross an untrusted network.

Browsers are allowed to call the API only from the origins in `--validator-api-allowed-origins`. By default the only allowed origin is the API's own listening URL, for example `http://127.0.0.1:5055`. Repeat the option to allow more origins, for example a local dashboard.

## Endpoints

| Method and path | What it does |
|---|---|
| `GET /eth/v1/keystores` | List all validating keys, each with a `readonly` flag |
| `POST /eth/v1/keystores` | Import keystores, with optional slashing protection data |
| `DELETE /eth/v1/keystores` | Delete keys and return their slashing protection data |
| `GET /eth/v1/remotekeys` | List Web3Signer keys |
| `POST /eth/v1/remotekeys` | Import Web3Signer keys |
| `DELETE /eth/v1/remotekeys` | Delete Web3Signer keys |
| `GET /eth/v1/validator/{pubkey}/feerecipient` | Show a validator's fee recipient |
| `POST /eth/v1/validator/{pubkey}/feerecipient` | Set a validator's fee recipient |
| `DELETE /eth/v1/validator/{pubkey}/feerecipient` | Remove a validator's fee recipient, falling back to the default |
| `GET /eth/v1/validator/{pubkey}/gas_limit` | Show a validator's gas limit |
| `POST /eth/v1/validator/{pubkey}/gas_limit` | Set a validator's gas limit |
| `DELETE /eth/v1/validator/{pubkey}/gas_limit` | Remove a validator's gas limit, falling back to the default |
| `GET /eth/v1/validator/{pubkey}/graffiti` | Show a validator's graffiti |
| `POST /eth/v1/validator/{pubkey}/graffiti` | Set a validator's graffiti |
| `DELETE /eth/v1/validator/{pubkey}/graffiti` | Remove a validator's graffiti, falling back to the default |
| `POST /eth/v1/validator/{pubkey}/voluntary_exit` | Sign a voluntary exit and return it |
| `POST /eth/v2/debug/tracing/log_level` | Change the log level at runtime (Grandine-specific) |
| `POST /eth/v2/debug/tracing/trace_level` | Change the telemetry trace level at runtime (Grandine-specific) |

Successful responses use the standard formats: a JSON body with a `data` field, `202 Accepted` for a successful `POST` of a setting, and `204 No Content` for a successful `DELETE` of a setting. Errors return a JSON body with a `message` field. Bodies must be sent with `Content-Type: application/json`.

Every change through the API takes effect immediately, with no restart, and is recorded in [`validators.yml`](./validator_definitions.md), so it survives restarts.

## Examples

The examples set two shell variables first:

```bash
API=http://127.0.0.1:5055
TOKEN=$(cat ~/.grandine/hoodi/validator/api-token.txt)
```

### List keys

```bash
curl -s -H "Authorization: Bearer $TOKEN" $API/eth/v1/keystores | jq
```

```json
{
  "data": [
    { "validating_pubkey": "0x93247f22...", "readonly": true },
    { "validating_pubkey": "0xa1d1ad07...", "readonly": false }
  ]
}
```

`readonly: true` marks keys this endpoint cannot delete: keystores loaded from `--keystore-dir` and Web3Signer keys, which are listed here too. Keys imported through the API and keys in the legacy storage are `readonly: false`. Use `GET /eth/v1/remotekeys` to list and `DELETE /eth/v1/remotekeys` to remove Web3Signer keys.

### Import a keystore

The request carries the keystores as JSON strings, the passwords in the same order, and optionally the slashing protection history as an [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076) interchange JSON string. `jq` builds the body from files:

```bash
jq -n \
  --rawfile keystore /path/to/keystore-m_12381_3600_0_0_0-1700000000.json \
  --rawfile password /path/to/password.txt \
  --rawfile slashing /path/to/slashing-protection.json \
  '{keystores: [$keystore], passwords: [$password], slashing_protection: $slashing}' |
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @- \
  $API/eth/v1/keystores | jq
```

```json
{ "data": [ { "status": "imported", "message": null } ] }
```

Each keystore gets a status:

- `imported`: the key is signing now;
- `duplicate`: the key is already loaded and enabled;
- `error`: the keystore could not be imported, with the reason in `message`, for example a wrong password or a key that is already a remote signer key.

Imported keystores are written to `<data-dir>/<network>/validator/0x<pubkey>/keystore.json`, and their passwords to `<data-dir>/<network>/secrets/0x<pubkey>` with mode `600`. If the request carries slashing protection data, Grandine imports it before it starts signing with the keys. If the data is malformed or for another network, the whole request fails.

> **Warning:** Always send the slashing protection history of a key that has signed anywhere before. Without it Grandine logs `keystore import: slashing protection data is not provided!` and has no record of what the key signed elsewhere.

### Delete a keystore

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pubkeys": ["0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c"]}' \
  $API/eth/v1/keystores > delete-response.json

jq -r .slashing_protection delete-response.json > slashing-protection.json
```

Grandine stops signing with the key, removes its `validators.yml` entry, and deletes its keystore and password files. The response holds a status per key and the keys' slashing protection data. Keep that data if the key will run anywhere else. The statuses are:

- `deleted`: the key was removed;
- `not_active`: the key is not loaded, but slashing protection data exists for it, which is returned;
- `not_found`: the key is not known;
- `error`: the key could not be deleted, for example `key is read-only` for a key from `--keystore-dir`.

Deleting keys from the legacy `keystores.json` storage requires `--keystore-storage-password-file`. See [Managing validator keys](./key_management.md#legacy-key-storage).

### Remote keys

List the Web3Signer keys:

```bash
curl -s -H "Authorization: Bearer $TOKEN" $API/eth/v1/remotekeys | jq
```

Import a key that a Web3Signer serves:

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"remote_keys": [{"pubkey": "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81", "url": "http://SIGNER-HOST:9000"}]}' \
  $API/eth/v1/remotekeys | jq
```

A key Grandine holds locally is refused with `key already exists in a local keystore`, so that a local key is never handed to a signer. Importing a key that was loaded from `--web3signer-urls` but has no `validators.yml` entry records an entry for it, which lets you give it per-validator settings.

Delete a remote key:

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pubkeys": ["0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"]}' \
  $API/eth/v1/remotekeys | jq
```

Grandine stops using the key and removes its entry. If a signer listed in `--web3signer-urls` serves the key, it comes back on the next start, or at the next epoch with `--web3signer-refresh-keys-every-epoch`. See [Web3Signer](./web3signer.md).

### Fee recipient, gas limit and graffiti

```bash
PUBKEY=0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a

# Set
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"ethaddress": "0xYOUR-EXECUTION-ADDRESS"}' $API/eth/v1/validator/$PUBKEY/feerecipient
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"gas_limit": "60000000"}' $API/eth/v1/validator/$PUBKEY/gas_limit
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"graffiti": "my-staking-node"}' $API/eth/v1/validator/$PUBKEY/graffiti

# Show
curl -s -H "Authorization: Bearer $TOKEN" $API/eth/v1/validator/$PUBKEY/feerecipient | jq
curl -s -H "Authorization: Bearer $TOKEN" $API/eth/v1/validator/$PUBKEY/gas_limit | jq
curl -s -H "Authorization: Bearer $TOKEN" $API/eth/v1/validator/$PUBKEY/graffiti | jq

# Remove the per-validator value and fall back to the default
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $API/eth/v1/validator/$PUBKEY/feerecipient
```

How the endpoints behave:

- The `GET` endpoints return the value in effect: the validator's own setting, or else the process-wide default (`--suggested-fee-recipient`, `--default-gas-limit`, `--graffiti`). `GET .../gas_limit` falls back to the network's scheduled gas limit. `GET .../feerecipient` returns `404` when neither the validator nor the default sets one.
- The `POST` and `DELETE` endpoints need a `validators.yml` entry for the validator and return `404` without one. Keys loaded only from `--web3signer-urls` have no entry. Import them through `POST /eth/v1/remotekeys` first.
- A graffiti longer than 32 bytes is rejected with `400`.

See [Fee recipient, graffiti and gas limit](./fee_recipient.md) for how these settings are used.

### Sign a voluntary exit

> **Warning:** A voluntary exit cannot be undone. Once it is published, the validator leaves the active set and cannot rejoin. See [Voluntary exits, withdrawals and consolidations](./voluntary_exit.md) before you exit.

The endpoint signs an exit for a key the validator client holds, locally or through a Web3Signer, and returns it. It does not publish it:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  $API/eth/v1/validator/$PUBKEY/voluntary_exit > exit.json
```

Without the `epoch` query parameter the exit uses the current epoch. Add `?epoch=EPOCH` to set it. A key the validator client does not hold, or one the beacon chain does not know yet, returns `404`.

To exit, submit the signed message to a beacon node:

```bash
jq -c .data exit.json |
curl -s -X POST -H "Content-Type: application/json" --data @- \
  http://127.0.0.1:5052/eth/v1/beacon/pool/voluntary_exits
```

### Change the log level

These endpoints change logging without a restart, which on a validator client would cost a slot of duties. `target` is a module path and `level` one of `error`, `warn`, `info`, `debug` or `trace`:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target": "validator", "level": "debug"}' \
  $API/eth/v2/debug/tracing/log_level
```

`trace_level` takes the same body, with `target` optional, and applies to the telemetry output enabled with `--telemetry-metrics-url`. See [Logging](./logging.md).

## Command line options

- `--enable-validator-api` (disabled): run the validator API server.
- `--validator-api-address` (default `127.0.0.1`): address to listen on.
- `--validator-api-port` (default `5055`): port to listen on.
- `--validator-api-allowed-origins` (default: the API's own listening URL): `Access-Control-Allow-Origin` values for browsers. Repeat the option for several origins.
- `--validator-api-timeout` (default `10000`): request timeout in milliseconds.
- `--validator-api-token-file` (default `<data-dir>/<network>/validator/api-token.txt`, generated if missing): file with the bearer token. A file you pass must already exist.
- `--keystore-storage-password-file` (no default): password for the legacy `keystores.json` storage of keys imported by older versions. Needed to load those keys and to delete them.

See [Command line reference](./cli_options.md) for the full list.
