//
// Serializer for the StreamIdChunk (4-byte identifier). Needed because the Ethernet FCS inserter
// serializes the frame at fcsMode=computed. The length of the stream-ID extension (overhead) is
// modelled by a separate ByteCountChunk as padding; this chunk always carries the 32-bit id.
//

#ifndef FRER_EXPERIMENTS_STREAMIDCHUNKSERIALIZER_H
#define FRER_EXPERIMENTS_STREAMIDCHUNKSERIALIZER_H

#include "inet/common/packet/serializer/FieldsChunkSerializer.h"

namespace inet {

class StreamIdChunkSerializer : public FieldsChunkSerializer
{
  protected:
    virtual void serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const override;
    virtual const Ptr<Chunk> deserialize(MemoryInputStream& stream) const override;
};

} // namespace inet

#endif
