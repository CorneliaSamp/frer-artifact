//
// Implementation of the StreamIdChunk serializer, see StreamIdChunkSerializer.h.
//

#include "StreamIdChunkSerializer.h"

#include "StreamIdExtTag_m.h"
#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"

namespace inet {

Register_Serializer(StreamIdChunk, StreamIdChunkSerializer);

void StreamIdChunkSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    const auto& idChunk = staticPtrCast<const StreamIdChunk>(chunk);
    stream.writeUint32Be(idChunk->getId());
}

const Ptr<Chunk> StreamIdChunkSerializer::deserialize(MemoryInputStream& stream) const
{
    auto idChunk = makeShared<StreamIdChunk>();
    idChunk->setId(stream.readUint32Be());
    return idChunk;
}

} // namespace inet
