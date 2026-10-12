//
// Vector Recovery Algorithm (VRA) for 802.1CB, rebuilt to follow the standard (IEEE 802.1CB-2017, 7.4.3.4).
//
// Why bother: INET does ship FRER, but its recovery (StreamMerger) is only a simple duplicate
// filter - it remembers the last few seq numbers and drops repeats. There is no RecovSeqNum, no
// acceptance window and no reset timer. But that is exactly what I need, because my attacks (CR
// and RSD) exploit precisely that mechanic. So I inherit from StreamMerger (to keep all of INET's
// FRER wiring) and only replace the decision whether a frame is taken or not.
//

#ifndef FRER_EXPERIMENTS_IEEE8021CBRECOVERY_H
#define FRER_EXPERIMENTS_IEEE8021CBRECOVERY_H

#include <map>
#include <set>
#include <string>

#include "inet/protocolelement/redundancy/StreamMerger.h"

class Ieee8021cbRecovery : public inet::StreamMerger
{
  protected:
    // history length H. the acceptance window spans +/-(H-1), so 16 by default here
    int H = 16;

    // if no frame arrives for this long, the SRF does a reset and takes the next
    // frame as the new reference (take-any). this gap is exactly what RSD exploits
    omnetpp::simtime_t resetTimeout;

    // the actual state, all per output stream (hence the maps):
    std::map<std::string, int> recov;                      // RecovSeqNum, i.e. the current reference seq
    std::map<std::string, omnetpp::simtime_t> lastAccept;  // when the last accepted frame arrived (for the reset)
    std::map<std::string, std::set<int>> seen;             // which seq I have already seen in the window (for duplicates)

    // signed 16-bit difference. the seq numbers wrap mod 2^16, without this -1 would suddenly
    // be a huge number instead of actually -1 and the window would compute wrong
    static int s16(int x) { return ((x + 32768) % 65536) - 32768; }

  protected:
    virtual void initialize(int stage) override;
    virtual bool matchesSequenceNumber(const char *streamName, int sequenceNumber) const override;
    virtual void processPacket(inet::Packet *packet) override;
};

#endif
