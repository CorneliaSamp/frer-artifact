//
// Implementation of the VRA, see Ieee8021cbRecovery.h for the why.
// The flow is: the base class (PacketFilterBase) first asks matchesSequenceNumber() -> yes/no
// for each frame, and ONLY if yes does processPacket() run afterwards.
// So the decision is separated from the state update, which fits nicely because
// rogue frames (that get dropped) should not change the state anyway.
//

#include "Ieee8021cbRecovery.h"

#include <cstdlib>   // for std::abs

#include "inet/common/SequenceNumberTag_m.h"
#include "inet/protocolelement/redundancy/StreamTag_m.h"

using namespace inet;

Define_Module(Ieee8021cbRecovery);

void Ieee8021cbRecovery::initialize(int stage)
{
    // initialize the base class first, it fetches e.g. the mapping and bufferSize
    StreamMerger::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        // read our own two parameters from the ned/ini
        H = par("historyLength").intValue();
        resetTimeout = par("resetTimeout").doubleValue();
    }
}

// Here we only DECIDE whether the frame is accepted. const, so don't touch the state.
bool Ieee8021cbRecovery::matchesSequenceNumber(const char *streamName, int seq) const
{
    auto r = recov.find(streamName);
    // we don't know this stream yet -> this is the first frame -> take-any -> accept
    if (r == recov.end())
        return true;

    // if no frame came for too long, the SRF did a reset and takes the next
    // frame as the new reference. this is exactly the spot RSD exploits
    auto l = lastAccept.find(streamName);
    if (l != lastAccept.end() && (simTime() - l->second) >= resetTimeout)
        return true;

    int d = s16(seq - r->second);

    // outside the window -> rogue -> drop. |d|>=H means too far ahead OR too far
    // behind. this is where CR/RSD make the legit frames fall out once the reference was shifted
    if (std::abs(d) >= H)
        return false;

    // ahead but still in the window -> normal case, accept (the reference then moves along, see below)
    if (d > 0)
        return true;

    // d<=0: behind, in the window. accept, unless we already had this seq (then it's a duplicate)
    auto s = seen.find(streamName);
    return !(s != seen.end() && s->second.count(seq));
}

// The state update. runs ONLY for frames that were accepted before. important: a rogue
// frame never even gets here, so it changes neither RecovSeqNum nor the timer - just like the standard.
void Ieee8021cbRecovery::processPacket(Packet *packet)
{
    // find out which output stream the frame belongs to (exactly how the StreamMerger does it)
    const auto& streamInd = packet->findTag<StreamInd>();
    if (streamInd != nullptr) {
        auto inputStreamName = streamInd->getStreamName();
        if (mapping->containsKey(inputStreamName)) {
            std::string h = mapping->get(inputStreamName).stringValue();
            int seq = packet->getTag<SequenceNumberInd>()->getSequenceNumber();

            // fresh = stream is new, reset = nothing came for too long. in both cases take-any:
            // the reference is set completely anew and the history is cleared
            bool fresh = recov.find(h) == recov.end();
            bool reset = !fresh && (simTime() - lastAccept[h]) >= resetTimeout;
            if (fresh || reset) {
                recov[h] = seq;
                seen[h].clear();
                seen[h].insert(seq);
            }
            else {
                int d = s16(seq - recov[h]);
                // the reference only moves along forward. a frame accepted behind does NOT change
                // RecovSeqNum, that's also how it is in the standard
                if (d > 0)
                    recov[h] = seq;
                seen[h].insert(seq);
                // the history should only cover the window. old entries that have already
                // fallen out I throw away, otherwise the set would grow forever. test with HW values!
                for (auto it = seen[h].begin(); it != seen[h].end(); )
                    if (s16(*it - recov[h]) <= -H)
                        it = seen[h].erase(it);
                    else
                        ++it;
            }
            lastAccept[h] = simTime();
        }
    }
    // the rest (e.g. stripping the R-TAG at egress) the StreamMerger already does right,
    // so I just call it instead of writing it myself
    StreamMerger::processPacket(packet);
}
