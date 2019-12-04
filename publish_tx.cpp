#include "construct_tx.h"
#include "base58.h"
#include "attachinfo.h"
#include "GlobalProfile.h"
#include "key.h"
#include "pubkey.h"
#include "keystore.h"
#include "consensus/params.h"
#include "consensus/merkle.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sign.h"
#include "core_io.h"
#include "utilstrencodings.h"

using namespace std;

static int GetWitnessCommitmentIndex(CTransactionRef& tx)
{
    int commitpos = -1;
    for (size_t o = 0; o < tx->vout.size(); o++) {
        if (tx->vout[o].scriptPubKey.size() >= 38 && tx->vout[o].scriptPubKey[0] == OP_RETURN && tx->vout[o].scriptPubKey[1] == 0x24 && tx->vout[o].scriptPubKey[2] == 0xaa && tx->vout[o].scriptPubKey[3] == 0x21 && tx->vout[o].scriptPubKey[4] == 0xa9 && tx->vout[o].scriptPubKey[5] == 0xed) {
            commitpos = o;
        }
    }
    return commitpos;
}

static void UpdateUncommittedTxStructures(CTransactionRef& ptx, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(ptx);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && !ptx->HasWitness()) {
        CMutableTransaction tx(*ptx);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        ptx = MakeTransactionRef(std::move(tx));
    }
}

static vector<unsigned char> GenerateTokenCoinbaseCommitment(CTransactionRef& ptx, const Consensus::Params& consensusParams)
{
    vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(ptx);
    vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = TxWitnessMerkleRoot(NULL);
            CHash256().Write(witnessroot.begin(), 32).Write(&ret[0], 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*ptx);
            tx.vout.push_back(out);
            if (BUSINESSTYPE_TOKEN == tx.GetBusinessType() && TOKEN_CREATE == tx.tokenParam.nTokenType ){
                CTxOut out;
                if (tx.tokenParam.nValueLimit > 0) {
                    out.nValue = tx.tokenParam.nValueLimit;
                } else {
                    out.nValue = TOKEN_MAX_MONEY;
                }
                out.scriptPubKey = tx.vout[0].scriptPubKey;
            } else if (BUSINESSTYPE_TOKEN == tx.GetBusinessType() && TOKEN_APPEND == tx.tokenParam.nTokenType){

            }
            ptx = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedTxStructures(ptx, consensusParams);
    return commitment;
}

bool CreatePublishTx(string& strRawTx, const UniValue& params)
{
    // check params
    if(!params.exists("token_params"))
        return error("Missing token params");

    if(!params.exists("gas_symbol"))
        return error("Missing symbol");

    if(!params.exists("gas_vin") || !params["gas_vin"].isArray() || params["gas_vin"].empty())
        return error("Invalid gas vin, gas vin must be an array");

    if(!params.exists("gas_vout") || params["gas_vout"].empty())
        return error("Missing gas vout");

    // parse token params
    const string& strTokenParams = params["token_params"].get_str();
    vector<unsigned char> vchRet;
    DecodeBase58(strTokenParams, vchRet);

    string strTokenInfo = "";
    strTokenInfo.insert(strTokenInfo.begin(), vchRet.begin(), vchRet.end());

    UniValue tokenParams;
    tokenParams.read(strTokenInfo);

    // owner address
    const string& strTokenName = tokenParams["tokenName"].get_str();
    const string& strOwnerAddr = tokenParams["address"].get_str();
    CBitcoinAddress ownerAddr(strOwnerAddr);

    // maximum amount
    CAmount nMaxAmount = -1 * COIN;
    const string& strMaxAmount = tokenParams["maximum"].get_str();
    if(strMaxAmount.find("-") == string::npos)
        nMaxAmount = AmountFromValue(tokenParams["maximum"], strTokenName);

    // amount
    CAmount nAmount = AmountFromValue(tokenParams["number"], strTokenName);

    if(strTokenName == GlobalProfile::strGasPayCurrencySymbol)
    {
        if(nMaxAmount > 0)
            nMaxAmount *= COIN;
        nAmount *= COIN;
    }

    bool fIncrease = true;
    if(nMaxAmount > 0)
        fIncrease = (nMaxAmount - nAmount) > 0;

    // build raw tx
    CMutableTransaction mtx;
    mtx.strPayCurrencySymbol = strTokenName;
    mtx.tokenParam.nTokenType = TOKEN_CREATE;
    mtx.tokenParam.nValueLimit = nMaxAmount;
    mtx.tokenParam.nAdditional = fIncrease ? TOKEN_ISSUANCE : TOKEN_NOISSUANCE;

    // fill attach
    CAttachInfo attach;
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("hexString", strTokenParams));
    attach.addAttach(CAttachInfo::ATTACH_PUBTOKEN, obj);
    mtx.strAttach = attach.write();

    // fill gasToken
    BuildTxGasTokenPart(mtx, params);

    // fill simple vin
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << 0 << OP_0;

    // fill simple vout
    mtx.vout.resize(1);
    mtx.vout[0].scriptPubKey = GetScriptForDestination(ownerAddr.Get());
    mtx.vout[0].nValue = nAmount;
    if(fIncrease)
    {
        if(nMaxAmount < 0)
            mtx.vout.push_back(CTxOut(TOKEN_MAX_MONEY - nAmount, GetScriptForDestinationAppendToken(ownerAddr.Get())));
        else if(nMaxAmount > nAmount)
            mtx.vout.push_back(CTxOut(nMaxAmount - nAmount, GetScriptForDestinationAppendToken(ownerAddr.Get())));
    }

    // append fill vin and vout
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    GenerateTokenCoinbaseCommitment(tx, Params().GetConsensus());

    // sign (just for gasToken)
    CMutableTransaction rawTx(*tx);
    if(!SignTxGasTokenPart(rawTx, params))
        return false;

    strRawTx = EncodeHexTx(rawTx);
    LogPrintf("create a new publish tx: %s\n", rawTx.GetHash().GetHex());
    return true;
}
