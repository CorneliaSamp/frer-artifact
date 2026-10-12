package frer_experiments;

//
// Measurement subclass (see .cc/.h). Inherits StreamIdExtRecovery (identifier check + VRA state)
// unchanged and additionally records the RecovSeqNum trace as a vector. Enable with:
//   *.S4.bridging.streamRelay.merger.typename = "StreamIdExtRecoveryProbe"
//
simple StreamIdExtRecoveryProbe extends StreamIdExtRecovery
{
    parameters:
        @class(StreamIdExtRecoveryProbe);
        @signal[recovSeqNum](type=long);
        @statistic[recovSeqNum](title="RecovSeqNum (merged stream)"; record=vector; interpolationmode=none);
}
