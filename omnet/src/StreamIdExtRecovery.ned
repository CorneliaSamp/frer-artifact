package frer_experiments;

//
// Stream-ID-extension check at the recovery node (see .cc/.h). Subclass of the VRA; checks the
// identifier tag before the recovery decision, VRA logic inherited unchanged. Usage:
//   *.S4.bridging.streamRelay.merger.typename = "StreamIdExtRecovery"
//   *.S4.bridging.streamRelay.merger.streamSecret = <identifier value>
// Inherits historyLength/resetTimeout from Ieee8021cbRecovery.
//
simple StreamIdExtRecovery extends Ieee8021cbRecovery
{
    parameters:
        @class(StreamIdExtRecovery);
        int streamSecret;                      // expected identifier value (the extended stream ID)
        int attackerMaxBytes = default(0);     // >0: frames with byteLength <= value count as attacker -> idMatch/idFail statistics
}
