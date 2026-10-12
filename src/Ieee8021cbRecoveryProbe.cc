//
// Implementation of the measurement subclass, see Ieee8021cbRecoveryProbe.h.
// Instrumentation only: after the (unchanged) base processPacket, the current RecovSeqNum of the
// merged stream is emitted as a vector. No change to logic/state.
//

#include "Ieee8021cbRecoveryProbe.h"

using namespace inet;

Define_Module(Ieee8021cbRecoveryProbe);

void Ieee8021cbRecoveryProbe::initialize(int stage)
{
    Ieee8021cbRecovery::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
        recovSignal = registerSignal("recovSeqNum");
}

void Ieee8021cbRecoveryProbe::processPacket(Packet *packet)
{
    // first the verified base logic (updates recov[] for accepted frames)
    Ieee8021cbRecovery::processPacket(packet);
    // then record the current RecovSeqNum of the merged stream (measurement only)
    auto it = recov.find("FRER_Stream");
    if (it != recov.end())
        emit(recovSignal, (long)it->second);
}
