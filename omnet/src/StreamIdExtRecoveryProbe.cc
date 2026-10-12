//
// Implementation of the measurement subclass, see StreamIdExtRecoveryProbe.h.
// After the (unchanged, inherited) state logic the current RecovSeqNum is emitted.
// matchesPacket (the identifier check) runs in PacketFilterBase BEFORE processPacket -> frames with a
// wrong identifier never reach processPacket and cannot change recov[].
//
#include "StreamIdExtRecoveryProbe.h"

using namespace inet;

Define_Module(StreamIdExtRecoveryProbe);

void StreamIdExtRecoveryProbe::initialize(int stage)
{
    StreamIdExtRecovery::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
        recovSignal = registerSignal("recovSeqNum");
}

void StreamIdExtRecoveryProbe::processPacket(Packet *packet)
{
    // inherited VRA state logic (Ieee8021cbRecovery::processPacket) -> updates recov[]
    StreamIdExtRecovery::processPacket(packet);
    auto it = recov.find("FRER_Stream");
    if (it != recov.end())
        emit(recovSignal, (long)it->second);
}
