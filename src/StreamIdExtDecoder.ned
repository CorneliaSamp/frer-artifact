package frer_experiments;

import inet.protocolelement.redundancy.StreamDecoder;

//
// Stream-ID-extension decoder (recovery node), subclass of StreamDecoder. Usage:
//   *.S4.bridging.streamCoder.decoder.typename = "StreamIdExtDecoder"
//   *.S4.bridging.streamCoder.decoder.idBytes = <n>   (must match the encoder)
// Reads the identifier chunk, sets StreamIdInd, removes the chunk. Decode/handle logic inherited unchanged.
//
simple StreamIdExtDecoder extends StreamDecoder
{
    parameters:
        @class(StreamIdExtDecoder);
        int idBytes = default(4);
}
