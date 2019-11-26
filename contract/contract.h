#ifndef CONTRACT_H
#define CONTRACT_H

#include "uint256.h"
#include "pubkey.h"
#include "chainparams.h"

class CContractCodeID : public uint160
{
public:
    CContractCodeID() : uint160() {}
    CContractCodeID(const uint160& in) : uint160(in) {}
};

class CContractTXScript
{
 public:
     uint256 hash256;  // contract content hash
     CChainParams::Base58Type type;  // CChainParams::Base58Type
     CKeyID keyID;  // CKeyID
     CContractCodeID contractID;  // CContractCodeID

     CContractTXScript() = default;
     CContractTXScript(const uint256& hash256In, const CChainParams::Base58Type& typeIn,
             const CKeyID& keyIDIn, const CContractCodeID& contractIDIn)
        : hash256(hash256In)
        , type(typeIn)
        , keyID(keyIDIn)
        , contractID(contractIDIn) {}

     friend inline bool operator<(const CContractTXScript& a, const CContractTXScript& b) {
         return (a.hash256 < b.hash256 && a.type < b.type);
     }

     friend bool operator==(const CContractTXScript& a, const CContractTXScript& b) {
         return (a.hash256 == b.hash256);
     }

     bool isNull() const {
         return hash256.IsNull();
     }
};

#endif
