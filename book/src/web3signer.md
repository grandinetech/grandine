# Web3Signer

[Web3Signer](https://github.com/Consensys/web3signer) is a remote signing service. It holds the validator keys, and the validator client sends it signing requests over HTTP instead of holding the keys itself. That keeps the keys off the machine that talks to the network, lets one key store serve several validator clients in turn, and allows hardware security modules and cloud key vaults behind the signer.

Grandine supports Web3Signer in both the integrated validator client (`grandine`) and the separate one (`grandine vc`). Remote signing is the recommended setup for large or valuable validator sets.

> **Note:** Grandine applies its own [slashing protection](./slashing_protection.md) to remote keys too, before it sends a signing request. Enable Web3Signer's slashing protection database as well. It protects the key even if a second validator client ever reaches the same signer.

> **Warning:** A signer serving a key to two validator clients at once is as dangerous as running the key twice. Point exactly one validator client at each key.

## Two ways to configure the signer

Choose one, or combine them:

- **`--web3signer-urls`** loads keys in bulk: Grandine asks each signer for the keys it serves and runs all of them, or the subset given with `--web3signer-public-keys`. This is the simplest option when the signer manages the validator set. These keys are not written to [`validators.yml`](./validator_definitions.md).
- **`web3signer` entries in `validators.yml`** declare keys one by one, created by hand or with `POST /eth/v1/remotekeys` on the [Keymanager API](./keymanager_api.md). Use them for per-validator settings, such as fee recipients, gas limits or graffiti, and for TLS options to reach the signer.

## Loading keys with `--web3signer-urls`

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --web3signer-urls http://SIGNER-HOST:9000 \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

With the separate validator client:

```bash
grandine vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --web3signer-urls http://SIGNER-HOST:9000 \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

Give the signer's base URL. Grandine calls `/api/v1/eth2/publicKeys` to list keys and `/api/v1/eth2/sign/{pubkey}` to sign, relative to the host, so any path in the URL is ignored. Several signers are given as separate values: `--web3signer-urls http://signer-1:9000 http://signer-2:9000`.

On startup Grandine logs the keys it got from each signer:

```text
loaded 12 validator key(s) from Web3Signer at http://SIGNER-HOST:9000/
```

To run only some of the keys a signer serves, list them:

```bash
--web3signer-public-keys 0x93247f22...,0xb301803f...
```

The list applies to every `--web3signer-urls` signer. A listed key that no signer serves is not loaded.

### When keys are fetched

- **On startup**, Grandine fetches the key list of every signer.
- **Every epoch**, it fetches again from any signer that has not answered with keys yet: one that was unreachable or returned an empty list. Grandine logs `Web3Signer at URL did not return any validator keys. It will retry to fetch keys again in the next epoch.`
- **With `--web3signer-refresh-keys-every-epoch`**, it fetches from every signer every epoch, so that keys added to a signer start signing without a restart. A refresh only adds keys. A key removed from the signer stays loaded until the next restart, and its signing requests fail in the meantime. A refresh also brings back a remote key deleted through the Keymanager API if a `--web3signer-urls` signer still serves it, or if it had a `validators.yml` entry when Grandine started.

Keys loaded from `--web3signer-urls` have no `validators.yml` entry, so:

- they use the process-wide defaults: `--suggested-fee-recipient`, `--default-gas-limit` and `--graffiti`;
- the Keymanager API rejects per-validator settings for them with `404`;
- `enabled: false` in `validators.yml` does not stop them. Narrow the keys with `--web3signer-public-keys` instead.

To give one of them its own settings, give it an entry. Import it through `POST /eth/v1/remotekeys` (this records an entry even for a key already loaded from a URL), or add the entry by hand. The URL keeps loading all its other keys as before.

## Declaring keys in `validators.yml`

A `web3signer` entry names a key and the signer that serves it:

```yaml
- enabled: true
  pubkey: "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
  type: web3signer
  url: http://SIGNER-HOST:9000
  fee_recipient: "0x0000000000000000000000000000000000000002"
  graffiti: "my-staking-node"
```

Grandine loads these keys on every start, with no `--web3signer-urls` needed. A URL named only by entries loads only the keys declared for it, plus any key listed in `--web3signer-public-keys` that it serves. A declared key the signer does not serve is skipped, with a warning:

```text
Web3Signer at URL does not serve declared validator 0x...; it will not be loaded
```

Remote keys imported through the Keymanager API get such entries automatically. See [Keymanager API](./keymanager_api.md#remote-keys).

A key that Grandine holds locally, in a keystore or the legacy storage, is never sent to a signer, even if a signer also serves it.

### TLS and mutual TLS

There are no command line options for TLS material. To reach a signer behind a private certificate authority, or one that requires a client certificate, set the options on a `web3signer` entry:

```yaml
- enabled: true
  pubkey: "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
  type: web3signer
  url: https://SIGNER-HOST:9000
  root_certificate_path: /etc/grandine/signer-ca.pem
  client_identity_path: /etc/grandine/grandine-client.p12
  client_identity_password: "YOUR-P12-PASSWORD"
  request_timeout_ms: 5000
```

- `root_certificate_path`: a PEM certificate added to the trusted roots.
- `client_identity_path` and `client_identity_password`: a PKCS#12 file with the client certificate and key, for mutual TLS. An empty password is used if `client_identity_password` is omitted.
- `request_timeout_ms`: the timeout of each signing request, in milliseconds. Without it, `--request-timeout` applies (default `30000`).

Grandine builds one HTTP client for all Web3Signer requests, so these options apply to every signer, including the ones in `--web3signer-urls`. All enabled entries that set them must set the same values. Grandine refuses to start if two entries differ. Entries without TLS options use the same client.

## Performance

Remote signing adds a network round trip to every signature. Keep the signer close to the validator client, on the same host or a low-latency link. Signatures needed by a deadline in the slot (attestations, blocks, aggregates and sync committee messages) are all requested at once. The larger batches signed once per epoch, selection proofs and builder registrations, are limited to 32 requests in flight so that they do not flood the signer.

## Command line options

- `--web3signer-urls` (no default): Web3Signer base URLs whose keys are loaded. Space-separated. Web3Signer is not used through the command line without it.
- `--web3signer-public-keys` (no default, which loads every key): comma-separated keys to load from the `--web3signer-urls` signers.
- `--web3signer-refresh-keys-every-epoch` (disabled): fetch the key list of every signer every epoch, adding keys without a restart.
- `--web3signer-api-urls`: deprecated alias of `--web3signer-urls`.
- `--request-timeout` (default `30000`): default request timeout in milliseconds, used for signing requests unless `request_timeout_ms` is set.

See [Command line reference](./cli_options.md) for the full list.
