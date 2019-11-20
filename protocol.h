#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "serialize.h"

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    enum {
        MESSAGE_START_SIZE = 4,
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = 4,
        CHECKSUM_SIZE = 4,

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

    CMessageHeader(const MessageStartChars& pchMessageStartIn);
    CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(FLATDATA(pchChecksum));
    }

    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    uint32_t nMessageSize;
    uint8_t pchChecksum[CHECKSUM_SIZE];
};

#endif
