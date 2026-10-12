# Measurement procedure

- No gPTP. All timestamps are taken at the receiver against a single clock, so the latency numbers
  are receiver-relative and do not carry any cross-host clock offset. This is deliberate: the
  attacks do not need synchronised clocks and I did not want a gPTP offset in the latency figures.
- Hosts send untagged; the VLAN is assigned at the access port.
- Each run is PRE / ACTIVE / POST, 20 s each. The attack runs only in ACTIVE, so every run carries
  its own before/after control and a recovery check.
- Legitimate and injected frames are separated by payload size, so the discriminator sits outside
  the fields FRER looks at.
- The recovery-node counters (passed / discarded / reset) are sampled before and after each
  injection and reported as deltas. Note that `discarded` lumps normal duplicate elimination
  together with out-of-range rejections, so a single discard's reason is not recoverable from the
  counters alone.
- Runs are checked against a capture-integrity gate before they go into the aggregates; runs that
  fail the gate are dropped and reported as dropped.
