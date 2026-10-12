package frer_experiments;

import inet.protocolelement.redundancy.StreamEncoder;

//
// Stream-ID-extension encoder (talker side), subclass of StreamEncoder. Usage:
//   *.talker.bridging.streamCoder.encoder.typename = "StreamIdExtEncoder"
//   *.talker.bridging.streamCoder.encoder.streamSecret = <identifier value>
// Appends an identifier chunk (the extended stream ID) to the frame; VLAN/PCP mapping inherited unchanged.
//
simple StreamIdExtEncoder extends StreamEncoder
{
    parameters:
        @class(StreamIdExtEncoder);
        int streamSecret;                // per-stream identifier value (the extended stream ID)
        int idBytes = default(4);        // length of the stream-ID extension in bytes
        bool randomId = default(false);  // true=attacker: carries a RANDOM value from [0,idSpace) per frame (guessing attempt)
        int idSpace = default(1);        // identifier space 2^b for randomId
}
