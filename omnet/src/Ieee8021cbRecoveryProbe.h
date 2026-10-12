//
// Measurement subclass of the VRA: ONLY for recording the RecovSeqNum trace for the displacement
// figure. Inherits the complete acceptance logic unchanged from Ieee8021cbRecovery (module A stays
// untouched) and emits the current RecovSeqNum as a signal after each accepted frame. Changes
// NOTHING in the decision/state -> the attack results (A_loss etc.) are identical.
//

#ifndef FRER_EXPERIMENTS_IEEE8021CBRECOVERYPROBE_H
#define FRER_EXPERIMENTS_IEEE8021CBRECOVERYPROBE_H

#include "Ieee8021cbRecovery.h"

class Ieee8021cbRecoveryProbe : public Ieee8021cbRecovery
{
  protected:
    omnetpp::simsignal_t recovSignal = -1;

    virtual void initialize(int stage) override;
    virtual void processPacket(inet::Packet *packet) override;
};

#endif
