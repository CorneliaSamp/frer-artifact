//
// Measurement subclass of StreamIdExtRecovery: identical to Ieee8021cbRecoveryProbe, but with the
// identifier check in front. It inherits the stream-ID check (matchesPacket) AND the VRA state logic
// (processPacket) UNCHANGED and emits the current RecovSeqNum after every ACCEPTED frame. Pure
// instrumentation: it changes neither the identifier decision nor the state -> A_loss/PDR identical to
// StreamIdExtRecovery. Purpose: record RecovSeqNum(t) under attack + mitigation.
//
#ifndef FRER_EXPERIMENTS_STREAMIDEXTRECOVERYPROBE_H
#define FRER_EXPERIMENTS_STREAMIDEXTRECOVERYPROBE_H

#include "StreamIdExtRecovery.h"

class StreamIdExtRecoveryProbe : public StreamIdExtRecovery
{
  protected:
    omnetpp::simsignal_t recovSignal = -1;

    virtual void initialize(int stage) override;
    virtual void processPacket(inet::Packet *packet) override;
};

#endif
