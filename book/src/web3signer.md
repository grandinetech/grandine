## Web3Signer

Grandine has a built-in validator that supports [Web3Signer](https://github.com/ConsenSys/web3signer). This is a recommended way to use Grandine's built-in validator with sensitive keys. We also recommend using Web3signer's built-in slashing protection even though the built-in validator has slashing protection too. Grandine automatically refreshes the validators list from the given Web3Signer instances.

There are two ways to use a Web3Signer; choose the one that fits your setup, or combine them both. Pass the signer's URLs with `--web3signer-urls` to load its keys in bulk and let the signer decide which keys Grandine runs. This is the simplest option when the signer manages the validator set. Declare `web3signer` entries in [`validators.yml`](./validator_definitions.md) instead when you need per-validator control, such as individual fee recipients, gas limits or graffiti, or TLS options for reaching the signer.

Keys served by a signer passed with `--web3signer-urls` are fetched from the signer directly. Grandine loads all of them, unless `--web3signer-public-keys` narrows the set, and refreshes them on every start (and every epoch with `--web3signer-refresh-keys-every-epoch`). These keys are **not** written to [`validators.yml`](./validator_definitions.md). The Web3Signer is authoritative for them, so removing a key on the signer removes it from Grandine on the next refresh, with no file to edit. Such validators have no `validators.yml` entry, so they cannot take per-validator settings through the Keymanager API. A `POST` of a fee recipient, gas limit, or graffiti for them is rejected with `404`, and they use the process-wide defaults.

To give one its own settings, give it a `validators.yml` entry. Import it through `POST /eth/v1/remotekeys` (this records an entry even for a key already loaded from a URL), or add the entry by hand. Each URL keeps its own set of keys to load, so adding an entry for one validator never changes which keys are loaded for the others. A URL that loads everything keeps doing so.

Grandine only loads keys the signer actually serves. A declared key that the signer does not serve is skipped, with a warning naming it. This applies both to a `validators.yml` `web3signer` entry and to a `--web3signer-public-keys` pubkey.

Remote keys imported through the Keymanager API (`POST /eth/v1/remotekeys`) *are* recorded in `validators.yml` and fetched again on the next start. A `web3signer` entry there may also declare TLS options for reaching the signer: `root_certificate_path` (a PEM certificate for a private CA), `client_identity_path` and `client_identity_password` (a PKCS#12 client identity for mutual TLS), and `request_timeout_ms`. Grandine builds a single Web3Signer HTTP client, so at most one distinct set of these options may appear across all entries. There are no command line options for this TLS material, so a signer behind a private CA or requiring mutual TLS must be configured through `validators.yml` entries.

### Relevant command line options

* `--web3signer-urls` - list of Web3Signer URLs. Web3Signer is not used if this option is not set.
* `--web3signer-public-keys` - list of public keys to use from Web3Signer. When set, it restricts the keys loaded from the `--web3signer-urls` URLs to those listed; when omitted, every key each URL serves is loaded. (A URL named by a `validators.yml` `web3signer` entry loads only that entry's keys, independently of this option.)
* `--web3signer-refresh-keys-every-epoch` - refetches keys from Web3Signer once every epoch. This overwrites changes done via the Keymanager API.
