# Validator definitions (validators.yml)

Grandine records the validators it manages in `validators.yml`, in the validator directory: `<data-dir>/<network>/validator/validators.yml`, which is `~/.grandine/<network>/validator/validators.yml` by default. For each validator the file records where its key comes from (a keystore file, the legacy key storage, or a Web3Signer), whether it is enabled, and its per-validator settings such as the fee recipient and graffiti.

Grandine creates and maintains the file. You can also edit it by hand while Grandine is stopped. The integrated validator client (`grandine`) and the separate one (`grandine vc`) use it the same way. `grandine bn` runs no validators and does not read it.

## What the file contains

The file records:

- keystores discovered in `--keystore-dir`;
- keystores imported through the [Keymanager API](./keymanager_api.md);
- keys in the legacy `keystores.json` storage (see [Migration from older versions](#migration-from-older-versions));
- remote keys imported through `POST /eth/v1/remotekeys`, and `web3signer` entries you add by hand.

It is not always a complete list of running validators. Keys known only through a Web3Signer passed with [`--web3signer-urls`](./web3signer.md) are fetched from the signer on every start and are not written here. For them the signer is authoritative. Because they have no entry, they use the process-wide defaults (`--suggested-fee-recipient`, `--default-gas-limit`, `--graffiti`), and the Keymanager API rejects per-validator settings for them with `404`. To configure such a validator on its own, give it an entry: import it through `POST /eth/v1/remotekeys` (which records an entry even for a key already loaded from a URL), or add a `web3signer` entry by hand.

## How the file is populated

On every start, Grandine loads the file, then adds entries for keys it finds that have none yet:

- keystores in `--keystore-dir`;
- keys in the legacy `keystores.json` storage.

This is additive. An existing entry always wins: discovery never overwrites settings, changes the key source of an entry, or re-enables a disabled entry. While Grandine runs, the file changes only through the Keymanager API, and each change is written to disk at once.

With `--in-memory`, the file is neither read nor written, and the definitions exist only for the life of the process.

## Format

The file is a YAML list with one entry per validator. Every entry has `pubkey` and `type`. The other fields are optional.

| Field | Applies to | Meaning |
|---|---|---|
| `pubkey` | all | Validator public key, `0x`-prefixed hex |
| `type` | all | `local_keystore`, `keystore_storage` or `web3signer` |
| `enabled` | all | `true` (default) or `false`. A disabled validator is not loaded |
| `description` | all | Free-form note |
| `fee_recipient` | all | Overrides `--suggested-fee-recipient` |
| `gas_limit` | all | Overrides `--default-gas-limit` |
| `graffiti` | all | Overrides `--graffiti`. At most 32 bytes |
| `builder_proposals` | all | `false` always uses the local payload |
| `builder_boost_factor` | all | Percentage applied to the builder's bid, overriding `--default-builder-boost-factor` |
| `prefer_builder_proposals` | all | `true` always prefers the builder's payload |
| `keystore_path` | `local_keystore` | Path of the EIP-2335 keystore file |
| `keystore_password_path` | `local_keystore` | Path of a file holding the keystore password |
| `keystore_password` | `local_keystore` | Inline keystore password. Takes precedence over `keystore_password_path` |
| `url` | `web3signer` | Web3Signer base URL |
| `root_certificate_path` | `web3signer` | PEM certificate of a private CA to trust |
| `client_identity_path` | `web3signer` | PKCS#12 client identity for mutual TLS |
| `client_identity_password` | `web3signer` | Password of the PKCS#12 file. Empty if omitted |
| `request_timeout_ms` | `web3signer` | Request timeout for the signer, in milliseconds |

The three builder fields are resolved in this order: `prefer_builder_proposals: true` wins, then `builder_boost_factor`, then `builder_proposals: false`, and otherwise `--default-builder-boost-factor` applies. See [Builder API and MEV](./builder_api_and_mev.md).

### `local_keystore`

An [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) keystore file on disk:

```yaml
- enabled: true
  pubkey: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
  type: local_keystore
  keystore_path: /home/user/validator_keys/keystore-m_12381_3600_0_0_0-1700000000.json
  keystore_password_path: /home/user/passwords/keystore-m_12381_3600_0_0_0-1700000000.txt
  fee_recipient: "0x0000000000000000000000000000000000000001"
  graffiti: "my-staking-node"
```

The entry must give `keystore_password` or `keystore_password_path`. Without either, Grandine fails to start with `validator 0x... declares neither keystore_password nor keystore_password_path`.

A keystore stored under the validator directory, which is where keystores imported through the API go, can be deleted through the Keymanager API. A keystore stored anywhere else is read-only to the API.

### `web3signer`

Signing is delegated to a [Web3Signer](./web3signer.md):

```yaml
- enabled: true
  pubkey: "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
  type: web3signer
  url: https://signer.example:9000
  root_certificate_path: /etc/grandine/signer-ca.pem
  client_identity_path: /etc/grandine/grandine-client.p12
  client_identity_password: "YOUR-P12-PASSWORD"
  request_timeout_ms: 5000
  fee_recipient: "0x0000000000000000000000000000000000000002"
```

The TLS fields and `request_timeout_ms` configure the HTTP client Grandine uses for all Web3Signer requests. Grandine builds a single Web3Signer client, so all enabled entries that set any of these fields must set the same values. Entries without them use that client too.

### `keystore_storage`

The key lives in the legacy `keystores.json` storage. The entry needs nothing beyond `pubkey`:

```yaml
- enabled: true
  pubkey: "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c"
  type: keystore_storage
```

## File permissions

An entry may contain an inline password, so Grandine creates the file readable and writable only by its owner (mode `600`). It writes the file atomically through a temporary file next to it. If you change the permissions, they are kept across later saves.

## Editing the file by hand

Stop Grandine before you edit the file. Grandine keeps its own copy in memory and overwrites the file on the next Keymanager API change.

- **To add a validator**, add an entry. For a keystore, `keystore_path` and a password are enough. The key in the keystore must match `pubkey`.
- **To retire a validator**, set `enabled: false`. Deleting the entry is not enough when the key source is still there: a keystore left in `--keystore-dir`, or a key left in `keystores.json`, is added again on the next start.
- **To remove a `--keystore-dir` validator for good**, delete both the keystore file and the entry, or delete the file and set `enabled: false`. An enabled entry whose keystore file is missing stops Grandine at startup.

Grandine validates the file on startup and refuses to start when:

- two entries have the same `pubkey`;
- a `graffiti` is longer than 32 bytes;
- a keystore contains a key other than the declared `pubkey`;
- a keystore file or password file of an enabled entry cannot be read, or the password is wrong;
- enabled `web3signer` entries declare more than one distinct set of TLS or timeout options.

`enabled: false` keeps the key from its own entry out of the signer. It does not hide a key that a `--web3signer-urls` signer serves: that key is loaded from the URL anyway. Use `--web3signer-public-keys` to narrow the keys loaded from a URL.

## Keymanager API changes

Changes made through the [Keymanager API](./keymanager_api.md) are recorded in the file right away:

- A keystore imported with `POST /eth/v1/keystores` is written to `<validator directory>/0x<pubkey>/keystore.json`, and its password to `<data-dir>/<network>/secrets/0x<pubkey>`. The entry is a `local_keystore` entry with these paths. Importing a key whose entry is disabled re-enables it.
- A remote key imported with `POST /eth/v1/remotekeys` gets a `web3signer` entry without TLS options.
- Deleting a keystore through the API removes its entry and deletes its keystore and password files. Only keys under the validator directory and in the legacy storage can be deleted. Keystores from `--keystore-dir` and keys loaded from `--web3signer-urls` are read-only.
- Deleting a remote key removes its entry. A key served by a signer in `--web3signer-urls` is loaded again on the next start.
- Fee recipients, gas limits and graffiti set through the API are stored on the validator's entry. A request for a validator without an entry is rejected with `404`.

## Migration from older versions

Older versions of Grandine kept keys imported through the API encrypted in `keystores.json`, unlocked with `--keystore-storage-password-file`, and kept proposer settings in a separate database in the validator directory. Both migrate automatically on the first start of a version that uses `validators.yml`:

- Keys in `keystores.json` keep loading through `keystore_storage` entries, and `--keystore-storage-password-file` is still required for them. Importing such a keystore through the API again moves the key to its own keystore file and removes it from `keystores.json`. Once the storage is empty, Grandine deletes the file, and the password option is no longer needed.
- Settings from the proposer settings database are copied to the matching `validators.yml` entries, and the database is removed once every setting has found its validator. Settings for validators that have no entry yet are kept in the database for a later start, and Grandine logs `keeping the legacy proposer configs database`.

## Command line options

- `--keystore-dir` (no default): keystores discovered at startup and added as `local_keystore` entries.
- `--keystore-storage-password-file` (no default): password for the legacy `keystores.json` storage behind `keystore_storage` entries.
- `--suggested-fee-recipient`, `--default-gas-limit`, `--graffiti`, `--default-builder-boost-factor`: defaults for validators whose entry does not set the field.
- `--data-dir` (default `~/.grandine`): `validators.yml` is in `<data-dir>/<network>/validator`.

See [Command line reference](./cli_options.md) for the full list.
