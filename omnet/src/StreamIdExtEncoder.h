//
// Stream-ID-extension encoder (talker side). Subclass of INET's StreamEncoder: it does the encoder's
// unchanged work (VLAN/PCP tags) and additionally appends an identifier chunk to the end of the frame
// carrying the per-stream (unpredictable) identifier value = the extended stream ID. The chunk is
// frame content and survives the switches; on replication (S1) both member copies get the same chunk.
// App-agnostic: the talker application stays unchanged.
//

#ifndef FRER_EXPERIMENTS_STREAMIDEXTENCODER_H
#define FRER_EXPERIMENTS_STREAMIDEXTENCODER_H

#include "inet/protocolelement/redundancy/StreamEncoder.h"

class StreamIdExtEncoder : public inet::StreamEncoder
{
  protected:
    int streamSecret = 0;    // the per-stream identifier value (the extended stream ID)
    int idBytes = 4;         // length of the stream-ID extension in bytes (overhead), configurable
    bool randomId = false;   // true = attacker: a random value per frame (guessing attempt)
    int idSpace = 1;         // identifier space 2^b for randomId

  protected:
    virtual void initialize(int stage) override;
    virtual void processPacket(inet::Packet *packet) override;
};

#endif
