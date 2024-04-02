## Web3Signer

Grandine has a built-in validator that supports [Web3Signer](https://github.com/ConsenSys/web3signer). This is a recommended way to use Grandine's built-in validator with sensitive keys. We also recommend using Web3signer's built-in slashing protection even though the built-in validator has slashing protection too. Grandine automatically refreshes the validators list from the given Web3Signer instances.

### Relevant command line options

* `--web3signer-api-urls` - comma separated list of Web3Signer urls. Web3Signer is not used if this option is not set.
