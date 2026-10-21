# Managing validator keys

This page explains where Grandine gets validator keys from, how it finds keystores and their passwords, and how to add, remove and move keys safely. Everything here applies both to the integrated validator client (`grandine`) and to the separate one (`grandine vc`).

## Key sources

Grandine loads keys from these sources, all of which can be combined:

| Source | How keys get there | Removable through the Keymanager API |
|---|---|---|
| Keystore directory | `--keystore-dir` with `--keystore-password-file` or `--keystore-password-dir` | No, read-only |
| Keystores imported through the API | `POST /eth/v1/keystores` on the [Keymanager API](./keymanager_api.md) | Yes |
| Legacy key storage (`keystores.json`) | API imports made by older Grandine versions | Yes, with `--keystore-storage-password-file` |
| Web3Signer | `--web3signer-urls`, `web3signer` entries in `validators.yml`, or `POST /eth/v1/remotekeys` | Remote keys only, through `DELETE /eth/v1/remotekeys` |

Every key Grandine manages locally, and every remote key imported through the API, gets an entry in [`validators.yml`](./validator_definitions.md). That file also holds per-validator settings. Keys that only a `--web3signer-urls` signer serves get no entry. See [Web3Signer](./web3signer.md).

## Where key files live

With the default data directory, the files for a network are under `~/.grandine/<network>/`:

```text
~/.grandine/hoodi/
├── validator/
│   ├── validators.yml                    validator definitions and per-validator settings
│   ├── slashing_protection.sqlite        slashing protection database
│   ├── api-token.txt                     Keymanager API token (with --enable-validator-api)
│   ├── 0x<pubkey>/keystore.json          keystores imported through the Keymanager API
│   ├── validator_key_cache_0x<hash>.json key cache (with --use-validator-key-cache)
│   └── keystores.json                    legacy key storage, from older versions only
└── secrets/
    └── 0x<pubkey>                        passwords of keystores imported through the API
```

Pass `--data-dir` to use another parent directory. The layout below it stays the same. Keystores loaded with `--keystore-dir` stay where they are and are never copied.

## Loading keystores from a directory

`--keystore-dir` points to a directory of [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) keystores, such as the `validator_keys` directory that ethstaker-deposit-cli writes. It must be combined with exactly one of `--keystore-password-file` and `--keystore-password-dir`.

On every start, Grandine scans the directory:

- Only the top level is scanned. Subdirectories are not searched.
- Files ending in `.json` and files without an extension are read as keystores. Files with any other extension are ignored.
- Files whose names start with `deposit_data` are skipped with a warning, so the deposit data file can stay in the directory.
- Any other file that is not a valid keystore stops Grandine with `Failed to load a keystore from file ...`. Keep only keystores in the directory, and no subdirectories without an extension.
- A keystore without a `pubkey` field is skipped with a warning.
- A keystore whose public key already has an entry in `validators.yml` is not added again. The existing entry, including its settings, wins.

New keystores are added to `validators.yml` as `local_keystore` entries with the keystore path and the password file path. Pass an absolute path to `--keystore-dir`, because the paths are recorded as given.

### One password for all keystores

When all keystores share a password, as they do when they were generated in one run of ethstaker-deposit-cli, put the password in a file:

```bash
printf '%s' 'YOUR-KEYSTORE-PASSWORD' > /path/to/password.txt
chmod 600 /path/to/password.txt

grandine \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt
```

### One password per keystore

When the keystores have different passwords, put each password in its own file in a directory and pass `--keystore-password-dir`. Each password file is named after its keystore:

- for a keystore named `NAME.json`, the password file is `NAME.txt`;
- for a keystore without an extension, the password file has exactly the same name.

```text
/path/to/validator_keys/keystore-m_12381_3600_0_0_0-1700000000.json
/path/to/validator_keys/keystore-m_12381_3600_1_0_0-1700000000.json
/path/to/passwords/keystore-m_12381_3600_0_0_0-1700000000.txt
/path/to/passwords/keystore-m_12381_3600_1_0_0-1700000000.txt
```

```bash
grandine vc \
  --network hoodi \
  --beacon-node-urls http://BN-HOST:5052 \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-dir /path/to/passwords
```

> **Note:** Grandine decides between the two modes by checking whether the password path is a directory. Passing a directory to `--keystore-password-file` therefore also works as a password directory. Passing both options at once is refused.

### Password format

Grandine reads the whole password file and, as EIP-2335 requires, normalizes it to NFKD and removes control characters. A trailing newline is therefore ignored, as are tabs and other control characters anywhere in the password. Passwords in `validators.yml` (`keystore_password_path` or an inline `keystore_password`) are treated the same way.

## Validator key cache

Keystores are encrypted with a deliberately slow key derivation function, so decrypting hundreds of keystores on every start takes time. `--use-validator-key-cache` makes Grandine save the decrypted keys in an encrypted cache file in the validator directory. On the next start, keys found in the cache are not decrypted again.

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --use-validator-key-cache
```

How the cache works:

- It covers keystore files: the ones from `--keystore-dir` and the ones imported through the API. Web3Signer keys and the legacy storage are not cached.
- It is encrypted with the passwords of all cached keystores together, and its file name (`validator_key_cache_0x<hash>.json`) is derived from the keystores' UUIDs. A different set of keystores uses a different cache file. An old cache file left behind can be deleted.
- If the cache cannot be read, Grandine logs `Unable to load validator key cache` and decrypts the keystores as usual.

> **Note:** The cache holds the same secret keys as the keystores, protected by the same passwords. Protect it like the keystores and include it in the same access controls.

## Adding keys

There are three ways to add a validator:

1. **Without a restart, through the Keymanager API.** `POST /eth/v1/keystores` imports a keystore with its password and, ideally, its slashing protection history. The key starts signing right away and is kept across restarts. See [Keymanager API](./keymanager_api.md).
2. **Without a restart, through a Web3Signer.** Import a remote key with `POST /eth/v1/remotekeys`, or add the key to a signer listed in `--web3signer-urls` and run with `--web3signer-refresh-keys-every-epoch`. See [Web3Signer](./web3signer.md).
3. **With a restart, through the keystore directory.** Copy the keystore (and, with `--keystore-password-dir`, its password file) into `--keystore-dir` and restart Grandine. The directory is only scanned at startup.

Whichever way you choose, import the key's slashing protection history first if it ever signed anywhere else. See [Slashing protection](./slashing_protection.md).

## Removing and disabling keys

- **Keys imported through the API** are removed with `DELETE /eth/v1/keystores`. Grandine stops signing with them right away, deletes the keystore file, its password file and the `validators.yml` entry, and returns the keys' slashing protection data. Save that data if the key will run elsewhere.
- **Remote keys** are removed with `DELETE /eth/v1/remotekeys`.
- **Keystores from `--keystore-dir`** are read-only: the API reports them as `readonly: true` and refuses to delete them. To remove one, stop Grandine, delete the keystore file, and remove its entry from `validators.yml` or set `enabled: false` on it. Do both: an entry whose keystore file is gone stops Grandine at startup, and a keystore file left in the directory is discovered again if its entry is removed.

To keep a key on disk but stop using it, set `enabled: false` on its entry in `validators.yml` and restart. Grandine logs `validator 0x... is disabled in validators.yml and will not be loaded`. Discovery never re-enables a disabled entry. See [Validator definitions](./validator_definitions.md).

## Legacy key storage

Before `validators.yml` existed, Grandine kept keystores imported through the Keymanager API in a single encrypted file, `keystores.json`, in the validator directory, unlocked with the password in `--keystore-storage-password-file`.

New imports now go to separate keystore files, and existing installations migrate on their own:

- Keys in `keystores.json` get `keystore_storage` entries in `validators.yml` and keep loading. They still need `--keystore-storage-password-file`.
- Importing such a keystore through the API again moves the key out of `keystores.json` into its own keystore file.
- Deleting such a key through the API also needs `--keystore-storage-password-file`. Without it the request fails with `password for decrypting keystores is missing, run Grandine with --keystore-storage-password-file to provide it`.
- When the last key leaves `keystores.json`, Grandine deletes the file, and the password option is no longer needed.

## Moving validators between machines

Moving a validator is the riskiest routine operation for a staker, because a short overlap between the old and the new signer is enough to get slashed. Follow this order:

1. Make sure the new machine is ready: the beacon node is synced, Grandine is configured, and it starts cleanly without the keys.
2. Stop the old validator client and make sure it cannot restart: disable its service, or remove the keys from it. If the old client is not Grandine, follow its documentation.
3. Export the slashing protection data from the old client. On Grandine:

   ```bash
   grandine --network mainnet interchange export /path/to/slashing-protection.json
   ```

4. Delete the keys from the old machine, or at least make sure nothing there loads them.
5. Import the slashing protection data on the new machine before its first start with the keys:

   ```bash
   grandine --network mainnet interchange import /path/to/slashing-protection.json
   ```

   Through the Keymanager API, you can pass the interchange data in the same request that imports the keystores instead.
6. Load the keys on the new machine and start it. Enable `--detect-doppelgangers` for extra safety. See [Doppelganger protection](./doppelganger_protection.md).
7. Watch the logs and the validators' attestations for the next few epochs.

If you are not sure that the old machine is stopped for good, wait at least two epochs (about 13 minutes) after it last signed before you start the new one. A missed epoch costs a little. A slashing costs much more.

For moving keys from the integrated validator client to a separate one on the same machine, see [Validator client](./validator_client.md#moving-keys-from-the-integrated-validator-client-to-grandine-vc).

## Security

- Generate keys offline, keep the mnemonic offline, and never copy it to the staking machine.
- Make password files, the `secrets` directory and `validators.yml` readable only by the user that runs Grandine. Grandine creates `validators.yml` and API-imported password files with mode `600` itself.
- For large or valuable validator sets, keep keys off the staking machine with a [Web3Signer](./web3signer.md).
- See [Security best practices](./security.md).

## Command line options

- `--keystore-dir` (no default): directory with EIP-2335 keystore files to load at startup. Requires a password option.
- `--keystore-password-file` (no default): file with the password for all keystores in `--keystore-dir`. Conflicts with `--keystore-password-dir`.
- `--keystore-password-dir` (no default): directory with a password file per keystore. Conflicts with `--keystore-password-file`.
- `--keystore-storage-password-file` (no default): password for the legacy `keystores.json` storage of keys imported by older versions.
- `--use-validator-key-cache` (disabled): cache decrypted keys for faster startup.
- `--data-dir` (default `~/.grandine`): parent directory of `<network>/validator` and `<network>/secrets`.

See [Command line reference](./cli_options.md) for the full list.
