package frer_experiments;

import inet.protocolelement.redundancy.StreamMerger;

//
// Our VRA recovery. inherits from INET's StreamMerger so we keep all the FRER wiring,
// but swaps out the decision logic (see .cc). you plug it into the scenario by setting
// the merger type at the recovery node to this module, e.g.:
//   *.S4.bridging.streamRelay.merger.typename = "Ieee8021cbRecovery"
//
simple Ieee8021cbRecovery extends StreamMerger
{
    parameters:
        int historyLength = default(16);              // H, i.e. the window +/-(H-1)
        double resetTimeout @unit(s) = default(1s);   // when a reset kicks in after silence
        @class(Ieee8021cbRecovery);
}
