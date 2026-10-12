# Grandine — project review profile

## What it is

- Ethereum consensus client: beacon node, validator client, slasher, HTTP API. Rust, one Cargo
  workspace of about 70 crates.
- Runs on mainnet with real stake. Speed and low memory are advertised product properties.
- The consensus specification is the definition of correct behaviour. Spec test vectors, downloaded
  by `make test`, are the conformance gate.
- Unfinalized states are kept in memory with structural sharing. Finalized blocks and states are
  stored on disk in libmdbx.
- `eth2_libp2p`, `dedicated_executor`, `hive`, `grandine-snapshot-tests` and
  `slashing-protection-interchange-tests` are git submodules. They are other repositories and follow
  their own rules.

## What a real failure is

Seven classes. Each carries its own severity rule, and a finding states the facts that rule needs.

- **Divergence from the specification.** Behaviour that differs from the specification for some
  input. Two code paths that must agree and no longer do are a divergence, and so is an optimisation
  that returns a different result from what it replaced for any input, or a change applied to one
  fork module and missing from another that needs it. Severity follows how far the effect reaches:
  - critical when it changes what the node accepts as valid, what it treats as canonical, or what it
    produces and signs. Every Grandine node then decides the same way, against the rest of the
    network.
  - major when the node's own view of the chain stays correct and the effect is confined to how it
    serves or communicates with other parties.
- **Validator loss.** Graded by what the validator stands to lose:
  - critical when it can be slashed;
  - major when its rewards fall, because a duty is missed, late or performed against the wrong
    state.
- **Untrusted input.** Anything arriving from outside the process: peers, API clients, the execution
  engine, builders, remote servers.
  - A panic reachable from untrusted input is always critical.
  - Work, memory or storage with no bound is graded by comparing what the sender spends to produce
    the input with what Grandine spends to handle it:
    - not reported when producing the input requires breaking a cryptographic primitive or solving
      a problem believed intractable;
    - minor when the two costs are of the same order;
    - major when the sender's cost is significantly lower than Grandine's;
    - critical when the sender's cost is negligible, or when Grandine's cost grows faster than
      linearly in the size of the input.
- **Stored data.** A change after which data written by an earlier version is handled differently.
  - critical when it is read without error and yields a value other than the one written;
  - major when it can no longer be read.
- **Performance.** A regression is graded by the slowdown of the affected operation:
  - critical when the node can no longer keep up with the chain, because work that must finish
    within a slot no longer does;
  - major at 1.5x or more;
  - minor from 10% up to that;
  - not reported below 10%.

  Avoidable work is the same value computed where it already exists, computed again elsewhere from
  the same inputs, or computed and then discarded. In code the change adds or touches it is graded
  by what removing it would save on the affected operation, with the same thresholds, and never
  above major.
- **Resource blowup.** Memory or disk use, sustained or at its peak, rising above what the same
  workload needed before the change:
  - critical when the growth has no bound, or is large enough to exhaust a machine that ran the
    previous version within its limits;
  - major when it is bounded, the node survives it, and it is 1.5x or more;
  - minor from 10% up to that;
  - not reported below 10%.
- **Secret exposure.** Key material or credentials reaching a log, an API response or any other
  output. Always critical.

## Blast radius

Three groups depend on the node. A defect is weighed by which of them it reaches and what it costs
them. One that reaches several takes the highest severity among them.

- **Validators.** They have stake at risk and are paid per duty.
  - Most of their income depends on duties performed within a fraction of a slot. A delay in block
    import, head selection, duty computation, block production or publication lowers rewards with
    no error appearing anywhere.
  - A missed duty costs its reward and often a penalty on top. A slashable message costs part of the
    stake and forces the validator out.
  - Every duty is driven through the Beacon API and its event stream, whether the validator client
    is Grandine's or another vendor's, and whether it talks to the node directly or through
    middleware that splits a validator across several nodes. A wrong, late or missing answer there
    becomes a wrong, late or missing duty.
  - Clients that use several beacon nodes compare their answers or fail over between them. A node
    that keeps answering while stale or wrong defeats that protection; one that fails visibly does
    not.
  - They detect trouble through metrics and logs. A metric that stops, or changes meaning, removes
    the alert that would have caught the next failure.
  - Anything that lowers a validator's rewards is major. Anything that puts its stake at risk is
    critical.
- **Full node operators.** They have no stake. They run the node to drive an execution client, and
  to supply chain data, blob data, light-client data or checkpoint states to services built on top.
  - A beacon node that stalls stops its execution client, and everything behind that client stops
    with it.
  - Their consumers act on Beacon API answers without re-checking them. An answer that is wrong but
    well-formed does more harm than an error.
  - They serve data to peers for the retention periods the specification sets. A node that cannot
    serve what it is obliged to is scored down and disconnected.
  - A defect that reaches only this group is major when it stops the node or makes it serve wrong
    data, and minor when it degrades service.
- **Archival node operators.** They keep the full history to answer questions about the past, and
  feed explorers, indexers, analytics and the accounting of staking protocols.
  - They query in bulk: every slot or epoch of a range, several requests at once, against states
    that must be reconstructed. Cost per historical query and behaviour under concurrent queries
    matter more to them than cost at the head.
  - Historical answers flow into payouts and published figures. A wrong one is not re-checked
    downstream.
  - Historical queries share the machine with following the chain. Query load that starves block
    processing or fork choice takes the whole node down.
  - They size disk and memory to the archive. Unexpected growth of either is an outage.
  - Rebuilding an archive takes days to weeks. A change that forces a rebuild costs them that long
    without history.

Whatever the group:

- A wrong result propagates into the head, the duties and every API answer derived from the state.
  Nothing downstream re-checks it, and a node that diverged or corrupted its database has no repair
  short of a resync.
- A change to a generic parameter, trait or shared helper reaches every fork module and every caller.
  Check the callers the diff does not show.

## Reporting bar

- A finding that falls in one of the failure classes takes its severity from that class's rule, and
  supplies the facts the rule needs. Without them it is speculation and is not reported.
  - Divergence: the input or event sequence, the specification text it contradicts, and whether any
    node's view of the chain changes.
  - Validator loss: the duty affected, and whether the outcome is slashable.
  - Untrusted input: the path from the entry point to the defect, and for unbounded work both
    costs, the sender's and Grandine's.
  - Stored data: which stored value, and whether the read fails or succeeds with a different value.
  - Performance and resource blowup: the affected operation or resource, how often the path runs,
    and the estimated factor with the reasoning behind the estimate. For avoidable work, both
    sites, and why their inputs are the same.
- A defect that no class covers is still reported. Its severity follows from who it reaches and
  what it costs them, as set out under Blast radius.
- **Not reportable**: anything `cargo fmt` or the CI Clippy run already enforces, naming, missing doc
  comments, a refactor suggested for its own sake, a faster way to do work that is done only once,
  a hypothetical future requirement.
- Finding nothing is a valid answer.

## Code shape

Deviations here are findings, at minor unless they hide a defect.

- New code that duplicates a helper the workspace already has. Search before accepting one.
- A helper, trait, wrapper or generic with a single caller that only moves logic out of sight.
  Sharing identical text between unrelated concepts counts as this.
- Production code given a parameter, hook or signature whose only purpose is to keep a test working.
- A new table, key or stored record holding data that the stored states and blocks already determine.
- An on-disk encoding applied to some stored values of a kind and not to the others.
- A comment that restates its line, describes what the code used to be, narrates the change, or
  cannot be understood without decoding. A comment earns its place by stating what the code does not.
- A log line placed away from the action it reports.
- An accumulator loop where a closed-form expression gives the same result.

## Deliberate — do not report

- One module per fork in `transition_functions` and elsewhere, with code repeated between them.
  Proposing to merge them is not a finding.
- `// >` comments quoting the specification, and code that follows the specification's structure
  and names rather than Rust idiom. A quote that no longer matches the code beneath it is a finding.
- Long functions in spec-mirroring code.
- `unsafe_code` is forbidden workspace-wide. Lint choices in the root `Cargo.toml` carry their
  reasons in comments there and are not open for debate in a review.

## Where the rules live

- Root `Cargo.toml`, `[workspace.lints]`: the lint table, with the reasoning for each exception.
- `clippy.toml`: disallowed methods and types, each with its required replacement.
- `rustfmt.toml`, `rust-toolchain.toml`.
- `scripts/ci/clippy.bash` and `.github/workflows/ci.yml`: what CI runs. Clippy runs with
  `--all-targets --deny warnings`; `make check` does not build test targets.
- `book/src/`: user-facing behaviour and command-line options. A change to either that leaves the
  book stale is a finding.
- The Ethereum consensus specifications, for anything a `// >` comment quotes.
