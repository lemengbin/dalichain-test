#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <vector>
#include "protocol.h"
#include "consensus/params.h"

class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        // smart contract address defines.
        SPA_CONTRACT_ADDRESS, // The simple point asynchronous contract address.
        WNS_CONTRACT_ADDRESS, // The whole network synchronize contract address.
        WNA_CONTRACT_ADDRESS, // The whole network asynchronous contract address.

        REALNAME_ADDRESS,     // The real-name address.
        REALNAME_SPA_CONTRACT_ADDRESS, // The real-name simple point asynchronous contract address.
        REALNAME_WNS_CONTRACT_ADDRESS, // The real-name whole network synchronize contract address.
        REALNAME_WNA_CONTRACT_ADDRESS, // The real-name whole network asynchronous contract address.

        SECRET_SPA_CONTRACT_ADDRESS, // secret contract address for the certain node.

        MAX_BASE58_TYPES
    };

protected:
    Consensus::Params consensus;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    CMessageHeader::MessageStartChars pchMessageStart;

public:
    CChainParams();
    const Consensus::Params& GetConsensus() const { return consensus; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; }
};

const CChainParams &Params();

#endif
