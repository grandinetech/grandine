For the last couple of months, we were experimenting with another parallelization stage in [Grandine](https://github.com/sifraitech/grandine) - multiple hardforks support that could be used for The Safe Merge - a safer approach for The Merge. The idea is pretty simple - run two hardforks in parallel instead of doing a regular hardforking process when at any given time only one hardfork is running. Let's see how The Safe Merge would look:

The Happy Case

```
PoW            ------o~~~~X (Social consensus to stop building on PoW)
                      \
The Safe Merge      -- o~~-------- (Party)
                   /
Altair         ---o-------X (Social consensus to stop building on Altair)
```

The Not So Happy Case

```
PoW            ------o~~~~-------- (Eth PoW keeps running until successful merge)
                      \
The Safe Merge      -- o~~X (Social consensus to cancel the failed attempt)
                   /
Altair         ---o--------------- (Altair keeps running until successful merge)
```

The pros:

* This approach decreases motivation to mount a coordinated attack as The Safe Merge can be repeated until it's successful;
* Unlike a regular hardforking approach, a failure is not a big deal. Lessons learned and next attempt rescheduled;
* It's possible to achieve this scheme using existing clients with small changes - run two instances of clients (one is dedicated for The Safe Merge chain, another one for Altair).
* May allow merging earlier as it's OK to attempt to merge without covering attacks that are targeting the big-bang approach of The Merge.

The cons:

Some of the below were already given as a feedback on the Eth 2.0 Implementers call.

* Client teams are used to hotfixing broken hardfork instead of playing safe, so a safer approach of The Safe Merge may be an unusual experience for involved parties;
* The Safer Merge has a window (~) when transactions need to be accepted both on PoW and The Safe Merge chain until the social consensus, otherwise there is a risk that the transaction is only on the chain that social consensus decides to drop;
* Such social consensus is not that easy to coordinate;    
* Consumes more resources, but the increase is a relatively low problem given then costs of 32 ETH and the resources needed to run EL client;
* More configuration. Unless clients decide to implement multiple parallel hardforks support, but from our experience with Grandine it was a major rework even in the case of our lightweight approach.

