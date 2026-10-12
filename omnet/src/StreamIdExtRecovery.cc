//
// Implementation of the stream-ID-extension check, see StreamIdExtRecovery.h.
//

#include "StreamIdExtRecovery.h"

#include "StreamIdExtTag_m.h"

using namespace inet;

Define_Module(StreamIdExtRecovery);

void StreamIdExtRecovery::initialize(int stage)
{
    Ieee8021cbRecovery::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        streamSecret = par("streamSecret").intValue();
        attackerMaxBytes = par("attackerMaxBytes").intValue();
    }
}

// identifier check BEFORE the recovery decision.
bool StreamIdExtRecovery::matchesPacket(const Packet *packet) const
{
    auto idInd = packet->findTag<StreamIdInd>();

    // equality compare: the carried identifier must match the assigned stream-ID value.
    bool authorized = (idInd != nullptr) && (idInd->getId() == (uint32_t)streamSecret);

    // statistics: identifier hit/miss only for attacker frames (frame-size threshold).
    // legitimate frames (larger) are not counted here; they are authorized by construction.
    if (attackerMaxBytes > 0 && packet->getByteLength() <= attackerMaxBytes) {
        if (authorized) numIdMatchAtk++; else numIdFailAtk++;
    }

    if (!authorized) {
        numUnauthorized++;
        return false;   // identifier does not match -> drop, no state update
    }
    // identifier matches -> unchanged VRA decision (inherited matchesSequenceNumber via StreamMerger)
    return Ieee8021cbRecovery::matchesPacket(packet);
}

void StreamIdExtRecovery::finish()
{
    recordScalar("unauthorizedDropped", numUnauthorized);
    recordScalar("idMatchAttacker", numIdMatchAtk);
    recordScalar("idFailAttacker", numIdFailAtk);
    Ieee8021cbRecovery::finish();
}
