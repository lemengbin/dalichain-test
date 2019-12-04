#include "script/standard.h"
#include "script/script.h"
#include "hash.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "base58.h"
#include <vector>
#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;
CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

namespace
{
    class CScriptVisitor : public boost::static_visitor<bool>
    {
    private:
        CScript *script;
    public:
        CScriptVisitor(CScript *scriptin) { script = scriptin; }
        bool operator()(const CNoDestination &dest) const {
            script->clear();
            return false;
        }

        bool operator()(const CKeyID &keyID) const {
            script->clear();
            *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
            return true;
        }

        bool operator()(const CScriptID &scriptID) const {
            script->clear();
            *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
            return true;
        }

        bool operator()(const CContractAddress &address) const {
            script->clear();
            *script << OP_DUP << OP_HASH160 << ToByteVector(address.GetData()) << OP_CONTRACTKEYID << OP_EQUALVERIFY << OP_CHECKSIG;
            return true;
        }

        bool operator()(const CRealNameAddress &address) const {
            script->clear();
            CKeyID keyID;
            address.GetKeyID(keyID);
            *script << ToByteVector(keyID) << OP_CHECKREALNAMESIG;
            return true;
        }

        bool operator()(const CContractTXScript &contracTXScript) const {
            script->clear();
            if (CChainParams::Base58Type::SPA_CONTRACT_ADDRESS == contracTXScript.type ||
                    CChainParams::Base58Type::WNS_CONTRACT_ADDRESS == contracTXScript.type ||
                    CChainParams::Base58Type::REALNAME_SPA_CONTRACT_ADDRESS == contracTXScript.type ||
                    CChainParams::Base58Type::REALNAME_WNS_CONTRACT_ADDRESS == contracTXScript.type)
            {
                CContractAddress contractAddress = CContractAddress(contracTXScript.type, contracTXScript.keyID, contracTXScript.contractID);
                *script << OP_DUP << OP_HASH160 << ToByteVector(contracTXScript.hash256) << OP_CHECKCONTRACT << OP_DUP << ToByteVector(contractAddress.GetData())
                    << OP_EQUALVERIFY << OP_CONTRACTKEYID << OP_EQUALVERIFY << OP_CHECKSIG;
            } else {
                *script << ToByteVector(contracTXScript.hash256) << OP_CHECKCONTRACT;
            }
            return true;
        }
    };

    class CScriptVisitorAppendToken : public boost::static_visitor<bool>
    {
    private:
        CScript *script;
    public:
        CScriptVisitorAppendToken(CScript *scriptin) { script = scriptin; }

        bool operator()(const CNoDestination &dest) const {
            script->clear();
            *script << OP_1 << OP_DROP;
            return false;
        }

        bool operator()(const CKeyID &keyID) const {
            script->clear();
            *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG << OP_1 << OP_DROP;
            return true;
        }

        bool operator()(const CScriptID &scriptID) const {
            script->clear();
            *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL<< OP_1 << OP_DROP;
            return true;
        }

        bool operator()(const CContractAddress &address) const {
            script->clear();
            *script << OP_DUP << OP_HASH160 << ToByteVector(address.GetData()) << OP_CONTRACTKEYID << OP_EQUALVERIFY << OP_CHECKSIG;
            return true;
        }

        bool operator()(const CRealNameAddress &address) const {
            script->clear();
            CKeyID keyID;
            address.GetKeyID(keyID);
            *script << ToByteVector(keyID) << OP_CHECKREALNAMESIG << OP_1 << OP_DROP;
            return true;
        }

        bool operator()(const CContractTXScript &contracTXScript) const {
            script->clear();
            if (CChainParams::Base58Type::SPA_CONTRACT_ADDRESS == contracTXScript.type ||
                CChainParams::Base58Type::WNS_CONTRACT_ADDRESS == contracTXScript.type ||
                CChainParams::Base58Type::REALNAME_SPA_CONTRACT_ADDRESS == contracTXScript.type ||
                CChainParams::Base58Type::REALNAME_WNS_CONTRACT_ADDRESS == contracTXScript.type)
            {
                CContractAddress address = CContractAddress(contracTXScript.type, contracTXScript.keyID, contracTXScript.contractID);
                *script << OP_DUP << OP_HASH160 << ToByteVector(contracTXScript.hash256) << OP_CHECKCONTRACT << OP_DUP << ToByteVector(address.GetData()) 
                        << OP_EQUALVERIFY << OP_CONTRACTKEYID << OP_EQUALVERIFY << OP_CHECKSIG;
            } else {
                *script << ToByteVector(contracTXScript.hash256) << OP_CHECKCONTRACT;
            }
            return true;
        }
    };
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;
    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForDestinationAppendToken(const CTxDestination& dest)
{
    CScript script;
    boost::apply_visitor(CScriptVisitorAppendToken(&script), dest);
    return script;
}

CScript GetScriptForWitness(const CScript& redeemscript)
{
    CScript ret;

    txnouttype typ;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (Solver(redeemscript, typ, vSolutions)) {
        if (typ == TX_PUBKEY) {
            unsigned char h160[20];
            CHash160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160);
            ret << OP_0 << std::vector<unsigned char>(&h160[0], &h160[20]);
            return ret;
        } else if (typ == TX_PUBKEYHASH) {
            ret << OP_0 << vSolutions[0];
            return ret;
        }
    }
    uint256 hash;
    CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());
    ret << OP_0 << ToByteVector(hash);
    return ret;
}

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<vector<unsigned char> >& vSolutionsRet)
{
    // Templates
    static multimap<txnouttype, CScript> mTemplates, mTemplatesAppend;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));
    }

    if (mTemplatesAppend.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplatesAppend.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG << OP_1 << OP_DROP));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplatesAppend.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG << OP_1 << OP_DROP));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplatesAppend.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG << OP_1 << OP_DROP));
    }


    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == 20) {
            typeRet = TX_WITNESS_V0_KEYHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            typeRet = TX_WITNESS_V0_SCRIPTHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        return false;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    if (!scriptPubKey.IsTokenCreateOrAppendOut())
    {
        // Scan templates
        const CScript& script1 = scriptPubKey;
        BOOST_FOREACH(const PAIRTYPE(txnouttype, CScript)& tplate, mTemplates)
        {
            const CScript& script2 = tplate.second;
            vSolutionsRet.clear();

            opcodetype opcode1, opcode2;
            vector<unsigned char> vch1, vch2;

            // Compare
            CScript::const_iterator pc1 = script1.begin();
            CScript::const_iterator pc2 = script2.begin();
            while (true)
            {
                if (pc1 == script1.end() && pc2 == script2.end())
                {
                    // Found a match
                    typeRet = tplate.first;
                    if (typeRet == TX_MULTISIG)
                    {
                        // Additional checks for TX_MULTISIG:
                        unsigned char m = vSolutionsRet.front()[0];
                        unsigned char n = vSolutionsRet.back()[0];
                        if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                            return false;
                    }
                    return true;
                }
                if (!script1.GetOp(pc1, opcode1, vch1))
                    break;
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;

                // Template matching opcodes:
                if (opcode2 == OP_PUBKEYS)
                {
                    while (vch1.size() >= 33 && vch1.size() <= 65)
                    {
                        vSolutionsRet.push_back(vch1);
                        if (!script1.GetOp(pc1, opcode1, vch1))
                            break;
                    }
                    if (!script2.GetOp(pc2, opcode2, vch2))
                        break;
                    // Normal situation is to fall through
                    // to other if/else statements
                }

                if (opcode2 == OP_PUBKEY)
                {
                    if (vch1.size() < 33 || vch1.size() > 65)
                        break;
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_PUBKEYHASH)
                {
                    if (vch1.size() != sizeof(uint160))
                        break;
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_SMALLINTEGER)
                {   // Single-byte small integer pushed onto vSolutions
                    if (opcode1 == OP_0 ||
                            (opcode1 >= OP_1 && opcode1 <= OP_16))
                    {
                        char n = (char)CScript::DecodeOP_N(opcode1);
                        vSolutionsRet.push_back(valtype(1, n));
                    }
                    else
                        break;
                }
                else if (opcode1 != opcode2 || vch1 != vch2)
                {
                    // Others must match exactly
                    break;
                }
            }
        }
    } else {
        //check if it is real name append
        if (scriptPubKey.IsRealNameAppendHash())
        {
            typeRet = TX_REALNAME;
            vector<unsigned char> pubkeyHashBytes(scriptPubKey.begin()+1, scriptPubKey.begin()+21);
            vSolutionsRet.push_back(pubkeyHashBytes);
            return true;
        }
        // Scan templates
        const CScript& script1 = scriptPubKey;
        BOOST_FOREACH(const PAIRTYPE(txnouttype, CScript)& tplate, mTemplatesAppend)
        {
            const CScript& script2 = tplate.second;
            vSolutionsRet.clear();

            opcodetype opcode1, opcode2;
            vector<unsigned char> vch1, vch2;

            // Compare
            CScript::const_iterator pc1 = script1.begin();
            CScript::const_iterator pc2 = script2.begin();
            while (true)
            {
                if (pc1 == script1.end() && pc2 == script2.end())
                {
                    // Found a match
                    typeRet = tplate.first;
                    if (typeRet == TX_MULTISIG)
                    {
                        // Additional checks for TX_MULTISIG:
                        unsigned char m = vSolutionsRet.front()[0];
                        unsigned char n = vSolutionsRet.back()[0];
                        if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                            return false;
                    }
                    return true;
                }
                if (!script1.GetOp(pc1, opcode1, vch1))
                    break;
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;

                // Template matching opcodes:
                if (opcode2 == OP_PUBKEYS)
                {
                    while (vch1.size() >= 33 && vch1.size() <= 65)
                    {
                        vSolutionsRet.push_back(vch1);
                        if (!script1.GetOp(pc1, opcode1, vch1))
                            break;
                    }
                    if (!script2.GetOp(pc2, opcode2, vch2))
                        break;
                    // Normal situation is to fall through
                    // to other if/else statements
                }

                if (opcode2 == OP_PUBKEY)
                {
                    if (vch1.size() < 33 || vch1.size() > 65)
                        break;
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_PUBKEYHASH)
                {
                    if (vch1.size() != sizeof(uint160))
                        break;
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_SMALLINTEGER)
                {   // Single-byte small integer pushed onto vSolutions
                    if (opcode1 == OP_0 ||
                            (opcode1 >= OP_1 && opcode1 <= OP_16))
                    {
                        char n = (char)CScript::DecodeOP_N(opcode1);
                        vSolutionsRet.push_back(valtype(1, n));
                    }
                    else
                        break;
                }
                else if (opcode1 != opcode2 || vch1 != vch2)
                {
                    // Others must match exactly
                    break;
                }
            }
        }
    }

    // contract script
    if (scriptPubKey.IsContractAddress())
    {
        typeRet = TX_CONTRACT_ADDRESS;
        vector<unsigned char> addrBytes(scriptPubKey.begin()+3, scriptPubKey.begin()+44);
        vSolutionsRet.push_back(addrBytes);
        return true;
    }

    if (scriptPubKey.IsContractOutput())
    {
        typeRet = TX_CONTRACT_OUTPUT;
        vector<unsigned char> contractHashBytes(scriptPubKey.begin()+1, scriptPubKey.begin()+33);
        vSolutionsRet.push_back(contractHashBytes);

        if (scriptPubKey.size() == 83) {
            vector<unsigned char> addrBytes(scriptPubKey.begin()+38, scriptPubKey.begin()+79);
            vSolutionsRet.push_back(addrBytes);
        }
        return true;
    }

    if (scriptPubKey.IsPayToRealNamePubkeyHash())
    {
        typeRet = TX_REALNAME;
        vector<unsigned char> pubkeyHashBytes(scriptPubKey.begin()+1, scriptPubKey.begin()+21);
        vSolutionsRet.push_back(pubkeyHashBytes);
        return true;
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}
