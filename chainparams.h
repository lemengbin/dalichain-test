#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <vector>
#include "protocol.h"

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

        MAX_BASE58_TYPES
    };

protected:
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    CMessageHeader::MessageStartChars pchMessageStart;

public:
    CChainParams()
    {
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        // base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};


        base58Prefixes[SPA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,90);
        base58Prefixes[WNS_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,91);
        base58Prefixes[WNA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,92);
        // for real-name
        base58Prefixes[REALNAME_ADDRESS] = std::vector<unsigned char>(1,93);
        base58Prefixes[REALNAME_SPA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,94);
        base58Prefixes[REALNAME_WNS_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[REALNAME_WNA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,96);

        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
    }

    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; }
};

const CChainParams &Params();

#endif
