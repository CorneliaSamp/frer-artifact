package frer_experiments;

//
// Measurement subclass of the VRA (see .cc/.h). Inherits Ieee8021cbRecovery unchanged and
// additionally records the RecovSeqNum trace as a vector (for the displacement figure). Plug it in with:
//   *.S4.bridging.streamRelay.merger.typename = "Ieee8021cbRecoveryProbe"
//
simple Ieee8021cbRecoveryProbe extends Ieee8021cbRecovery
{
    parameters:
        @class(Ieee8021cbRecoveryProbe);
        @signal[recovSeqNum](type=long);
        @statistic[recovSeqNum](title="RecovSeqNum (merged stream)"; record=vector; interpolationmode=none);
}
