//
// Attacker injector (module B), see FrerInjectorApp.ned for the why.
// Only sendPacket() is overridden - everything else (timing, socket, lifecycle) comes from UdpBasicApp.
//

#ifndef FRER_EXPERIMENTS_FRERINJECTORAPP_H
#define FRER_EXPERIMENTS_FRERINJECTORAPP_H

#include <vector>

#include "inet/applications/udpapp/UdpBasicApp.h"

class FrerInjectorApp : public inet::UdpBasicApp
{
  protected:
    // legit talker frame interval -> used to estimate the current legit seq from time
    omnetpp::simtime_t productionInterval;
    // legit seq reference (CR: phase offset at t=0; RSD: resume seq)
    int seqBase = 0;
    // true = CR time ramp, false = RSD fixed anchor seq
    bool timeVarying = true;
    // true = BLIND open-loop: seq guessed uniformly at random, NO time reference, no feedback,
    // no adaptation. Takes precedence over timeVarying/burstSize/offsets.
    bool blind = false;
    // size of the seq space for blind guessing (16 bit = 65536). Only used in blind mode.
    int seqSpace = 65536;
    // true = append a guessed identifier value to the frame (mitigation evaluation).
    bool attachAuth = false;
    // size of the identifier space 2^b for guessing the identifier value. idSpace=1 -> always 0 (b=0, no mitigation).
    int idSpace = 1;
    // >0 = RSD burst mode (tracks bursty legit progression); productionInterval = burst period
    int burstSize = 0;
    // the forward offsets; the next one is taken cyclically per sent frame (one ramp cycle)
    std::vector<int> offsets;
    // re-anchor pause after each full cycle (0 = none)
    inet::clocktime_t cycleGap;
    // own counter just for rotating the offset (numSent from the parent stays the send numbering)
    int injCount = 0;

  protected:
    virtual void initialize(int stage) override;
    // the only intervention: chosen 802.1CB seq number instead of auto numbering
    virtual void sendPacket() override;
    // like sendPacket, but with a re-anchor pause after each full ramp cycle
    virtual void processSend() override;
};

#endif
