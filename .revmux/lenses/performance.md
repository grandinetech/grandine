---
description: time cost — work added to paths that run often, optimisations that do not deliver, and work done twice or thrown away
---
## Lens: performance

Find where the change makes the program spend more time, and where the code it touches spends
time on work that is already done somewhere else. Memory and disk use belong to another lens; time
is this one's whole subject.

Start from frequency, not from the code that looks expensive. For each function the change touches,
establish from its callers how often it runs and what its input scales with. The cost of a change
is that frequency multiplied by the time added per run, so a small addition on a path that runs
for every item of a large collection outweighs a large one on a path that runs once.

Look for:

- work whose amount now scales with a larger quantity than before, or with one that grows over the
  life of the node
- a change in complexity class: a lookup that became a scan, a single pass that became nested
- work moved inside a loop, or repeated per item where one pass over the whole collection served
- a result that used to be computed once, cached or carried along and is now recomputed
- a cache whose key or invalidation makes it miss on the path it exists for
- a copy of a large structure where a borrow or a shared reference served before, and a mutation
  that forces a structurally shared value to be copied in full
- hashing, signature verification, serialisation or compression applied to more data, or more often,
  than the result requires
- operations that used to be batched and are now issued one at a time: database reads and writes,
  verifications, messages
- a lock held across more work than before, or taken on a path many threads share
- blocking work placed on a thread or executor that other time-critical work waits on
- parallel work made sequential, and parallel work added where the pool is already saturated
- an allocation per item inside a loop that runs for every element of a large collection

When the change is itself an optimisation, check that it delivers:

- the fast path is reached by the inputs the node actually sees, not only by the ones it was
  written for
- the saving is not paid back elsewhere, by a slower fallback, a more expensive setup or a
  conversion at the boundary
- an optimisation that returns a different result from the code it replaced is a correctness
  defect. Report it as one

Look also for avoidable work in the code the change adds or touches. For each value there that is
expensive to produce, search the workspace, beyond the diff, for every other place that produces
that value and every place that consumes it. Report when one of these holds:

- a cache, a stored field or a value already in scope holds the same value, and the code computes
  it again
- another site computes the same value from the same inputs, earlier or later, and one result
  could serve both
- the code produces a value and then discards it, or uses only part of it, while something else
  will need it

Such a finding names both sites, shows that their inputs are the same and that nothing between
them changes those inputs, and estimates what removing the duplicate saves on the affected
operation. State what handing the value from one site to the other would require. How hard that is
does not decide whether to report. A faster way to do work that is done only once is not a finding.

For each finding, state the operation affected, how often it runs, and the factor by which it
slows down, or for avoidable work the share of the operation that would be saved.

Whether you may build and run code is set by the instructions of the review you are part of, not by
this lens. Where you may, measure the operation before and after the change under the same
conditions, and report both numbers with the command that produced them. Where you may not, give an
estimate with the reasoning behind it, say that it is an estimate, and name the measurement that
would confirm it.

Leave alone: cost on a path that runs once at startup or shutdown, a difference too small to reach
the project's reporting bar, and a faster algorithm for work that the change did not make slower
and that nothing else duplicates.
