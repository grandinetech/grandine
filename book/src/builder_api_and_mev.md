## Builder API and MEV

Grandine supports [Builder API](https://github.com/ethereum/builder-specs) for stakers that use MEV. Only a single builder URL can be passed to Grandine. Multiple builders can be used via relay such as [mev-boost](https://github.com/flashbots/mev-boost) or [mev-rs](https://github.com/ralexstokes/mev-rs). Grandine provides a configurable circuit breaker that disables external block building in certain conditions.

### Relevant command line options:

* `--builder-api-url` - external block builder URL (default: does not use any external builder);
* `--builder-disable-checks` - always specified external block builder without checking for circuit breaker conditions (default: disabled);
* `--builder-max-skipped-slots` - number of consecutive missing blocks to trigger circuit breaker condition and switch to a local execution engine for payload construction (default: `3`);
* `--builder-max-skipped-slots-per-epoch` - number of missing blocks in the last rolling epoch to trigger circuit breaker condition and switch to a local execution engine for payload construction (default: `5`).
