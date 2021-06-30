# Grandine: Parallelized Cross-Platform Proof-Of-Stake Consensus Implementation For Ethereum Networks

## Beacon Node

The Beacon Node is the main component of Grandine.
Let's try it out by syncing the Prater network.
You may use the [GUI](#gui) if you find that more comfortable.

Download [Grandine binary release](https://github.com/sifraitech/grandine/releases) for your platform and make it executable, then run one of the following commands in a terminal:
```shell
# Linux
./grandine-linux-0.1.0 --network prater

# macOS
./grandine-macos-0.1.0 --network prater

# Windows
./grandine-windows-0.1.0.exe --network prater
```

## Validator

The Validator is a built-in component that is activated if validator keys are passed to Grandine.
Let's try running Grandine with a new validator enabled on the Prater network:
- Setup Ethereum 1.0 node or use 3rd party service such as [Infura](https://infura.io/).
  Correctly choose the corresponding Ethereum 1.0 network.
  Görli is the right one for Prater.
- Acquire validator keys using [Launchpad](https://prater.launchpad.ethereum.org/en/) and extract to a local directory.
- Run the following command:
  ```shell
  ./grandine-0.1.0 --eth1-rpc-url ETH1-RPC-URL                               \
                   --network prater                                          \
                   --keystore-dir PATH-TO-VALIDATOR-KEYS-DIR                 \
                   --keystore-password-file PATH-TO-VALIDATORS-PASSWORD-FILE
  ```

## Slasher

The Slasher is another built-in component.
It turned off by default as it's not optimized yet.

## Slashing Protection

Grandine supports the [Slashing Protection Interchange Format](https://eips.ethereum.org/EIPS/eip-3076).
It's a must to migrate slashing protection data if you are switching between clients.
We also highly recommend waiting for a few epochs before starting validators on a new client.

## GUI

Grandine comes with an optional cross-platform Graphical User Interface.
The GUI was born from our own need to visualize validator performance so the GUI already features powerful performance tooling.
We are planning to extend the functionality significantly if the community will favor GUI.

![GUI](gui.png)

## HTTP API

HTTP API is partially implemented.
We expect to finalize it and release API documentation in the upcoming months.

## Cross Platform

Our current focus is 64-bit [Tier 1](https://doc.rust-lang.org/nightly/rustc/platform-support.html#tier-1) platforms.
We may consider supporting a particular [Tier 2](https://doc.rust-lang.org/nightly/rustc/platform-support.html#tier-2) platforms if there is sufficient demand for it.
Even though we provide native builds for multiple platforms, we primarily test Linux builds.

## Implementation

Our goal is to deliver original implementations for such core components as fork choice.
Apart from common libraries such as cryptography or networking, Grandine doesn't follow reference implementations.
This approach has already enabled us to find vulnerabilities in all other implementations and greatly contributes to Grandine's performance.

## Performance

Grandine can sync several times faster than other implementations.
CPUs with 16 threads or more may deliver a performance increase of up to ~1000% under certain conditions.
Some optimizations are not yet implemented, so there is room for even higher performance.
Grandine should be able to utilize an arbitrary number of CPU threads in upcoming releases.

## Snapshot Sync

Grandine is designed to load from an [anchor-state](https://github.com/ethereum/eth2.0-specs/blob/a553e3b18e77db954944d76994e40fb675b48009/specs/phase0/fork-choice.md#get_forkchoice_store).
Currently, Grandine stores and loads only its own transitioned states.
We are ready to add the snapshot sync support once deposit withdrawals are available.
Until then it's not clear is it worth weakening security by bringing trusted snapshots.

## Security

We take security as seriously as performance.
We have adopted various security practices such as peer-reviews and fuzzing, we do not commit any [unsafe](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) code, etc.

## Open Source

Grandine is funded by multiple parties such as private capital and European Union grants.
We are actively looking for options that would allow satisfying the obligations that came with these sources of funding and would allow us to open-source Grandine.

## Team

Grandine is built by [SIFRAI](https://twitter.com/sifraitech) core team led by [Saulius Grigaitis](https://twitter.com/sauliuseth).
We also involve academia in the early stages of new developments, however, the optimized production code is delivered by the core team.

## Research

Our core interest is the performance problems of proof-of-stake and sharding protocols.
Feel free to reach us if you are interested in collaborating on scientific research and peer-reviewed papers on modern scaling methods - zk-SNARKS, executable shards, cross-chains, and other techniques.

## Feedback

Feature requests and votes for them are welcome.
This will help figure out which upcoming features are the most important.

## Old CPUs

We currently do not provide builds for older CPUs.
Let us know if you get an "Illegal instruction" error.
This will help us decide whether we should provide separate builds that support older CPUs.

## Use at Your Own Risk

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
