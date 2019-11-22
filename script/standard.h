#ifndef STANDARD_H
#define STANDARD_H

#include <boost/variant.hpp>

#include "uint256.h"

enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
    TX_WITNESS_V0_SCRIPTHASH,
    TX_WITNESS_V0_KEYHASH,
    // contract
    TX_CONTRACT_ADDRESS,
    TX_CONTRACT_OUTPUT,
    // real-name
    TX_REALNAME,
    TX_REALNAME_CONTRACT_ADDRESS,
    TX_REALNAME_CONTRACT_OUTPUT
};

class CScript;
class CKeyID;
class CContractAddress;
class CRealNameAddress;
class CContractTXScript;
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript& in);
    CScriptID(const uint160& in) : uint160(in) {}
};

class CNoDestination
{
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

typedef boost::variant<CNoDestination, CKeyID, CScriptID, CContractAddress, CRealNameAddress, CContractTXScript> CTxDestination;
CScript GetScriptForDestination(const CTxDestination& dest);
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet);;

#endif
