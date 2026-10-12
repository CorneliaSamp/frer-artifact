//
// Implementation of the stream-ID-extension decoder, see StreamIdExtDecoder.h.
//

#include "StreamIdExtDecoder.h"

#include "StreamIdExtTag_m.h"

using namespace inet;

Define_Module(StreamIdExtDecoder);

void StreamIdExtDecoder::initialize(int stage)
{
    StreamDecoder::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
        idBytes = par("idBytes").intValue();
}

void StreamIdExtDecoder::processPacket(Packet *packet)
{
    // unchanged StreamDecoder work (sets StreamInd = stream handle)
    StreamDecoder::processPacket(packet);
    // read the identifier chunk at the end of the frame -> set Ind tag -> remove the chunk.
    // Legit frames carry a real StreamIdChunk at the end -> peek returns it directly.
    // Attacker frames have ApplicationPacket bytes there -> with PF_ALLOW_REINTERPRETATION the last
    // 4 B are read as a (wrong) identifier -> StreamIdExtRecovery drops them (mismatch).
    // PF_ALLOW_NULLPTR catches frames that are too short.
    auto chunk = packet->peekAtBack<StreamIdChunk>(B(4),
            Chunk::PF_ALLOW_REINTERPRETATION | Chunk::PF_ALLOW_NULLPTR);
    if (chunk != nullptr) {
        packet->addTagIfAbsent<StreamIdInd>()->setId(chunk->getId());
        packet->eraseAtBack(B(idBytes));   // remove identifier chunk (+ padding) -> clean frame onward
    }
    // otherwise: no Ind tag -> StreamIdExtRecovery drops it for missing credential
}
