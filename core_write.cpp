#include "core_io.h"
#include "streams.h"
#include "transaction.h"
#include "utilstrencodings.h"

std::string EncodeHexTx(const CTransaction& tx, const int serialFlags)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | serialFlags);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}
