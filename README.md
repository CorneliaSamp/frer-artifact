# FRER recovery-state experiments — code and configuration

Artifacts for the paper's simulation and testbed experiments. Anonymized for double-blind review.

The point of this repo is to make reproducible the things that are actually ours: the
standard-compliant Vector Recovery Algorithm in OMNeT++/INET (INET's own FRER recovery is just a
duplicate filter and has no RecovSeqNum / acceptance window / reset timer), the sequence-number
injector used for both attacks, and the mitigation (an extended, unpredictable per-stream
identifier). The physical results need specific TSN hardware, so for those we give the switch
configuration and the measurement procedure instead of expecting a rerun.

## Layout

```
omnet/src/            VRA, recovery-state probe, injector, test network (+ mitigation, see below)
omnet/simulations/    omnetpp.ini with every configuration used, plus the analysis scripts
testbed/injector/     raw-socket 802.1CB frame injector (C)
testbed/analysis/     scripts that turn the captures into the reported numbers
testbed/FRER_config.md, measurement.md
```

## OMNeT++

OMNeT++ 6.4.0, INET 4.7.0. Nothing in INET is patched; `Ieee8021cbRecovery` subclasses INET's
`StreamMerger` and only replaces the accept/drop decision, so the rest of INET's FRER chain stays
as-is. Build it next to your inet-4.7.0 checkout:

```
opp_makemake -f --deep -KINET_PROJ=../inet-4.7.0 -DINET_IMPORT \
  -I../inet-4.7.0/src -L../inet-4.7.0/src -lINET
make
```

Reproduce the simulation numbers:

```
cd omnet/simulations
./analyze_cr.sh CR_d3      # continuous racing, depth 3
./analyze_rsd.sh 200       # recovery state desync, sequence lead 200
```

`analyze_crhw.sh` / `analyze_rsdhw.sh` run the hardware-faithful replications (same rates, same
20 s window) for the sim-vs-hardware comparison. The history-length sensitivity runs are the same
configs with `H=8` in omnetpp.ini.

## Testbed

`testbed/injector` builds with a plain `cc tsn_inject.c -o tsn_inject`. It writes complete Layer-2
frames through an AF_PACKET socket, so it constructs the R-TAG and the sequence number itself and
does not touch legitimate traffic. `testbed/FRER_config.md` has the switch side and the config
pitfalls; `testbed/measurement.md` has how the runs are structured and how the counters are read.

## Mitigation (extended stream ID)

The `StreamIdExt*` modules implement the mitigation: the stream identity is extended by an
unpredictable per-stream identifier value, carried as a chunk in the frame (`StreamIdExtEncoder` on
the talker, `StreamIdExtDecoder` + `StreamIdExtRecovery` at S4). `StreamIdExtRecovery` subclasses the
VRA and only adds an equality check of the identifier *before* the recovery decision; the VRA logic
itself is inherited unchanged. An off-path attacker does not know the identifier and must guess it,
so only ~`2^-b` of its frames pass the gate (`idSpace = 2^b`).

Run the mitigation configs from `omnet/simulations` (sweep `idSpace` over `1, 2, 4, …` for the
identifier length `b = 0, 1, 2, …`):

```
../src/FRER_Experiments -u Cmdenv -c ID_P2 \
    --*.attacker.bridging.streamCoder.encoder.idSpace=16   # identifier factor (idMatch/idFail scalars)
../src/FRER_Experiments -u Cmdenv -c CR_d3_IDGATE \
    --*.attacker.bridging.streamCoder.encoder.idSpace=16   # legitimate-frame loss (PDR) over b
../src/FRER_Experiments -u Cmdenv -c RSD_IDGATE \
    --*.attacker.bridging.streamCoder.encoder.idSpace=16
```

`idSpace=1` (`b=0`) is the unprotected baseline. The modules are not needed to reproduce the attacks
alone — delete `omnet/src/StreamIdExt*` if you only want the attack side.

## License

To be released under a permissive open-source license on acceptance.
