//
// Carrier for the extended stream identifier inside the frame. The identifier value travels as a
// CHUNK (frame content) so it survives the switches (packet tags are stripped by the MacRelayUnit on
// forwarding). The StreamIdExtDecoder at the recovery node reads the chunk and turns it into an Ind
// tag for StreamIdExtRecovery; there is no relay between decoder and merger, so the tag survives up to
// the VRA (same as SequenceNumberInd).
//
// id = the per-stream identifier value (the extended stream ID). The chunk size models the length of
// the stream-ID extension (idBytes) as overhead.
//

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.common.TagBase;

namespace inet;

// Identifier chunk that travels in the frame from talker to recovery node (survives the switches).
class StreamIdChunk extends FieldsChunk
{
    uint32_t id = 0;
}

// Ind tag that the StreamIdExtDecoder builds from the chunk and that StreamIdExtRecovery checks before the VRA.
class StreamIdInd extends TagBase
{
    uint32_t id = 0;
}
