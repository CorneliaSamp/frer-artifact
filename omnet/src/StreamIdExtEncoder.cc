//
// Implementation of the stream-ID-extension encoder, see StreamIdExtEncoder.h.
//

#include "StreamIdExtEncoder.h"

#include "StreamIdExtTag_m.h"
#include "inet/common/SequenceNumberTag_m.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"

using namespace inet;

Define_Module(StreamIdExtEncoder);

void StreamIdExtEncoder::initialize(int stage)
{
    StreamEncoder::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        streamSecret = par("streamSecret").intValue();
        idBytes = par("idBytes").intValue();
        randomId = par("randomId").boolValue();
        idSpace = par("idSpace").intValue();
    }
}

void StreamIdExtEncoder::processPacket(Packet *packet)
{
    // unchanged StreamEncoder work (VLAN/PCP tags)
    StreamEncoder::processPacket(packet);
    // append the identifier chunk to the end of the frame (seq was set by the streamIdentifier)
    auto seqReq = packet->findTag<SequenceNumberReq>();
    if (seqReq != nullptr) {
        // padding for identifier lengths > 4 B (models the extended stream ID as overhead)
        if (idBytes > 4)
            packet->insertAtBack(makeShared<ByteCountChunk>(B(idBytes - 4)));
        // 4-B chunk right at the end (the serializer writes exactly 4 B)
        auto chunk = makeShared<StreamIdChunk>();
        uint32_t val = randomId
            ? (uint32_t)intuniform(0, idSpace - 1)   // attacker: guessed value from [0, idSpace)
            : (uint32_t)streamSecret;                // legitimate: the assigned identifier value
        chunk->setId(val);
        chunk->setChunkLength(B(4));
        packet->insertAtBack(chunk);
    }
}
