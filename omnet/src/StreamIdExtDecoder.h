//
// Stream-ID-extension decoder (recovery node). Subclass of INET's StreamDecoder: it does the decoder's
// unchanged work (StreamInd/handle) and additionally reads the identifier chunk at the end of the frame,
// turns it into a StreamIdInd tag for StreamIdExtRecovery and removes the chunk (clean frame onward).
// There is no relay/switch between this decoder and the merger, so the Ind tag survives up to the VRA.
//

#ifndef FRER_EXPERIMENTS_STREAMIDEXTDECODER_H
#define FRER_EXPERIMENTS_STREAMIDEXTDECODER_H

#include "inet/protocolelement/redundancy/StreamDecoder.h"

class StreamIdExtDecoder : public inet::StreamDecoder
{
  protected:
    int idBytes = 4;   // must match the StreamIdExtEncoder size

  protected:
    virtual void initialize(int stage) override;
    virtual void processPacket(inet::Packet *packet) override;
};

#endif
