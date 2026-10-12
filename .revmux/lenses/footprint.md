---
description: memory and disk use — what the change retains, for how long, and how many of them exist
---
## Lens: footprint

Find where the change makes the program hold more memory or write more to disk. Time cost belongs
to another lens; what is kept is this one's whole subject.

Start from retention, not from the allocation that looks large. For each value the change creates,
stores or keeps a reference to, establish from its owner three things: how big one of them is, how
many exist at once, and what event releases it. Footprint is the product of the first two for as
long as the third has not happened, so a few bytes added to something that exists once per item of
a large collection outweigh a large value that lives for one call.

Look for, in memory:

- a collection, cache, map or queue that grows with a quantity that has no ceiling, with no
  eviction tied to a limit or to an event that is certain to occur
- a bound counted in items when the items differ widely in size
- retention that ends at an event the node does not control. Whatever is released on that event is
  unbounded for as long as the event does not come
- a value that now lives longer than before: moved into a long-lived owner, captured by a task or
  closure that outlives the call, or held while waiting on something slow
- two versions of a structurally shared value that no longer share, so that each retained version
  costs a full copy
- a whole value built in memory where the code only needs to pass over it or read part of it
- large values alive at the same time that used to be alive one after another, including work
  spread across threads where each holds its own
- a producer feeding a slower consumer through a buffer with no limit and no backpressure
- a field, wrapper or indirection added to a type that is instantiated once per item of a large
  collection

Look for, on disk:

- a new kind of record, or more bytes in an existing one, written once per recurring unit. Multiply
  by how many units accumulate over the retention period
- data that is written and that no pruning path removes, and a pruning path that no longer covers
  everything the write path produces
- a stored value held in a less compact form than other values of its kind
- data stored that the database already determines
- a large value rewritten in full to change a small part of it
- intermediate data left behind when an operation fails or the process restarts

Judge the peak as well as the steady state. A level reached briefly during one operation exhausts a
machine as surely as one held for hours.

For each finding, state the resource, the size of one unit, how many units exist and for how long,
and the factor by which the total rises.

Whether you may build and run code is set by the instructions of the review you are part of, not by
this lens. Where you may, measure the resource before and after the change under the same
conditions, for long enough to show the effect, and report both numbers with the command that
produced them. Where you may not, give an estimate with the reasoning behind it, say that it is an
estimate, and name the measurement that would confirm it and how long it has to run.

Leave alone: short-lived allocations that do not change the peak, a difference too small to reach
the project's reporting bar, and a more compact alternative to something the change did not make
larger.
