## Validator Definitions

Grandine records the validators it manages in `validators.yml`, in the validator directory (`~/.grandine/<NETWORK>/validator` by default). For each validator, the file records where its key comes from (a keystore file, the legacy storage, or a Web3Signer) and its per-validator settings. Grandine creates and maintains the file automatically. It can also be edited by hand.

The file records the validators it manages: keystores, keys in the legacy storage, and remote keys imported through the Keymanager API. It is not a complete list of every running validator. Validators known *only* through a Web3Signer passed with [`--web3signer-urls`](./web3signer.md) are fetched from the signer on every start and are **not** recorded here. For those, the Web3Signer is authoritative. Because they have no entry, they use the process-wide proposer defaults, and the Keymanager API rejects per-validator settings for them with `404`. To configure such a validator individually, give it a `validators.yml` entry. Import it through `POST /eth/v1/remotekeys` (this records an entry even for a key already loaded from a URL), or add the entry by hand. See [Web3Signer](./web3signer.md).

### How the file is populated

On every start, Grandine re-seeds the file additively from its key sources:

* keystores discovered in `--keystore-dir`;
* keys in the legacy `keystores.json` storage (see [migration](#migration-from-older-versions) below).

An existing entry always wins. Re-seeding never overwrites settings or re-enables a disabled entry. Otherwise, entries are only changed by the [Keymanager API](#keymanager-api).

### Format

Every entry has `pubkey`, `type`, and `enabled` (defaults to `true`), and may carry these optional per-validator settings:

* `description` - free-form note;
* `fee_recipient`, `gas_limit`, `graffiti` - override the corresponding command line options;
* `builder_proposals`, `builder_boost_factor`, `prefer_builder_proposals` - override the builder boost factor (see [Builder API and MEV](./builder_api_and_mev.md)).

The remaining fields depend on `type`:

**`local_keystore`** - an [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) keystore file:

```yaml
- enabled: true
  pubkey: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
  type: local_keystore
  keystore_path: /home/user/.grandine/validator_keys/keystore-0.json
  keystore_password_path: /home/user/.grandine/secrets/keystore-0.txt
  fee_recipient: "0x0000000000000000000000000000000000000001"
  graffiti: "Grandine"
```

The password comes from `keystore_password_path`, or from an inline `keystore_password`, which takes precedence.

**`web3signer`** - signing delegated to a [Web3Signer](./web3signer.md):

```yaml
- enabled: true
  pubkey: "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
  type: web3signer
  url: https://signer.example
```

**`keystore_storage`** - the key lives in the legacy `keystores.json` storage. The entry needs nothing beyond `pubkey`:

```yaml
- enabled: true
  pubkey: "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c"
  type: keystore_storage
```

Because an entry may contain an inline password, Grandine creates the file readable only by its owner. Permissions you set on it are preserved across saves.

### Hand editing

* To retire a validator, set `enabled: false`. Removing an entry's line does not reliably retire it: Grandine re-seeds a `keystore_storage` validator from the storage, and re-discovers a `--keystore-dir` keystore, on the next start. A `keystore_storage` validator can also be deleted through the Keymanager API.
* Grandine validates the file on startup. Duplicate pubkeys, unparsable graffiti, or a keystore whose key does not match the declared `pubkey` prevent it from starting.

### Keymanager API

Grandine implements the standard [Keymanager API](https://ethereum.github.io/keymanager-APIs/), enabled with `--enable-validator-api`. Its changes are recorded in `validators.yml`:

* keystores imported through the API are written to `<validator directory>/0x<pubkey>/keystore.json`, with their passwords in the secrets directory (`~/.grandine/<NETWORK>/secrets` by default);
* only keys imported through the API can be deleted through it. Keystores from `--keystore-dir` and remote signers' keys are reported as read-only;
* deleting a remote key removes its entry. A key served by a signer listed in `--web3signer-urls` may be loaded again by the next start or key refresh;
* fee recipients, gas limits and graffiti set through the API are stored on the validator's entry. Requests for validators without an entry are rejected with `404`.

### Migration from older versions

Older versions of Grandine kept API-imported keys encrypted in `keystores.json` (unlocked with `--keystore-storage-password-file`) and proposer settings in a separate database. Both migrate automatically:

* keys in `keystores.json` keep loading through `keystore_storage` entries, and `--keystore-storage-password-file` is still required for them. Importing such a keystore through the API again upgrades the validator to keystore files and removes its key from `keystores.json`. Once the file is empty, Grandine deletes it and the password option is no longer needed;
* the proposer settings database is folded into `validators.yml` entries and removed once every setting has found its validator.
