//
// Stream-ID-extension check at the recovery node, realized as a thin subclass of the VRA
// (Ieee8021cbRecovery). It CHECKS the identifier tag BEFORE the recovery decision (in matchesPacket)
// and drops frames whose identifier does not match the assigned stream-ID value. The actual VRA logic
// (accept/duplicate/reset in matchesSequenceNumber and the state update in processPacket) is INHERITED
// and NOT changed. Because PacketFilterBase calls processPacket only for accepted frames, a dropped
// frame cannot change the RecovSeqNum.
//
// Conceptually = an identifier check after stream identification, before the SRF. (The ideal INET slot
// bridging.streamFilter is incompatible with the protocol registration in our manually configured FRER
// topology; hence the subclass solution in the working merger slot.)
//

#ifndef FRER_EXPERIMENTS_STREAMIDEXTRECOVERY_H
#define FRER_EXPERIMENTS_STREAMIDEXTRECOVERY_H

#include "Ieee8021cbRecovery.h"

class StreamIdExtRecovery : public Ieee8021cbRecovery
{
  protected:
    int streamSecret = 0;              // expected identifier value (the extended stream ID)
    int attackerMaxBytes = 0;          // >0: frame-size threshold for attacker detection (idMatch statistics)
    mutable long numUnauthorized = 0;   // counted in the const matchesPacket()
    mutable long numIdMatchAtk = 0;     // attacker frames with a correct identifier
    mutable long numIdFailAtk = 0;      // attacker frames with a wrong identifier

  protected:
    virtual void initialize(int stage) override;
    virtual bool matchesPacket(const inet::Packet *packet) const override;
    virtual void finish() override;
};

#endif
