//
// Implementation of the attacker injector, see FrerInjectorApp.h / .ned.
// sendPacket() builds the packet exactly like UdpBasicApp, but attaches ONE extra tag:
// SequenceNumberReq with a self-chosen number. The rest (building the R-TAG, encoding the VLAN,
// forwarding, decoding at S4) is done by INET's verified FRER chain, unchanged.
//

#include "FrerInjectorApp.h"

#include <cmath>   // std::floor

#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/common/SequenceNumberTag_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressResolver.h"

using namespace inet;

Define_Module(FrerInjectorApp);

void FrerInjectorApp::initialize(int stage)
{
    // parent first: it fetches sendInterval, destPort, socket etc. and schedules the first send.
    UdpBasicApp::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        productionInterval = par("productionInterval").doubleValue();
        seqBase = par("seqBase").intValue();
        timeVarying = par("timeVarying").boolValue();
        blind = par("blind").boolValue();
        seqSpace = par("seqSpace").intValue();
        attachAuth = par("attachAuth").boolValue();
        idSpace = par("idSpace").intValue();
        burstSize = par("burstSize").intValue();
        cycleGap = par("cycleGap");
        cStringTokenizer tok(par("offsets").stringValue());
        while (tok.hasMoreTokens())
            offsets.push_back(atoi(tok.nextToken()));
        if (offsets.empty())
            offsets.push_back(0);
    }
}

void FrerInjectorApp::sendPacket()
{
    // BLIND open-loop: seq guessed uniformly from [0, seqSpace). No time reference, no observation,
    // no feedback, no adaptation. Takes precedence over all other modes.
    int target;
    if (blind) {
        target = intuniform(0, seqSpace - 1);
    }
    else {
    // reference seq of the legit progression, depending on the mode:
    int legitEst;
    if (burstSize > 0) {
        // RSD burst mode: for burst b (=floor(t/period)) the last legit seq of the burst is
        // b*burstSize + (burstSize-1). productionInterval acts as the burst period here.
        int b = (int)std::floor(simTime().dbl() / productionInterval.dbl());
        legitEst = seqBase + b * burstSize + (burstSize - 1);
    }
    else if (timeVarying) {
        // CR: estimate the legit progression from time (no observation needed).
        legitEst = seqBase + (int)std::floor(simTime().dbl() / productionInterval.dbl());
    }
    else {
        // RSD single: fixed resume reference.
        legitEst = seqBase;
    }
    // chosen target seq = reference seq + the (rotating) attack offset.
    target = legitEst + offsets[injCount % offsets.size()];
    }

    // --- from here identical to UdpBasicApp::sendPacket(), only the one tag line is added ---
    std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(par("messageLength")));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);

    // Mitigation evaluation: the guessed identifier value is NOT attached here (application level, in
    // the UDP payload) but by the StreamIdExtEncoder of the attacker node at L2 (randomId mode) -
    // consistent with the legitimate path and without corrupting the UDP payload.

    // THE attack: self-chosen 802.1CB seq number. The seq numbers wrap mod 2^16, so mask it.
    // Ieee8021rTagEpdHeaderInserter.cc:36-41 copies this value 1:1 into the R-TAG.
    packet->addTag<SequenceNumberReq>()->setSequenceNumber(target & 0xFFFF);

    L3Address destAddr = chooseDestAddr();
    emit(registerSignal("packetSent"), packet);   // fills the inherited packetSent counter (sanity)
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
    injCount++;
}

// Like UdpBasicApp::processSend(), but after a FULL ramp cycle (offsets used up) it schedules
// the re-anchor pause cycleGap instead of sendInterval. During the pause the attacker injects
// nothing -> RecovSeqNum stays frozen -> legit catches up (mean_s ~ mean_g, bounded).
void FrerInjectorApp::processSend()
{
    sendPacket();
    // injCount was incremented in sendPacket; == 0 mod size means: just sent the last offset
    bool cycleDone = (cycleGap > CLOCKTIME_ZERO) && (injCount % (int)offsets.size() == 0);
    clocktime_t d = cycleDone ? cycleGap : par("sendInterval");
    if (stopTime < CLOCKTIME_ZERO || getClockTime() + d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleClockEventAfter(d, selfMsg);
    }
    else {
        selfMsg->setKind(STOP);
        scheduleClockEventAt(stopTime, selfMsg);
    }
}
