#include "construct_tx.h"
#include "base58.h"
#include "attachinfo.h"
#include "key.h"
#include "pubkey.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sign.h"
#include "core_io.h"
#include "utilstrencodings.h"

#define CONTRACT_VERSION    1

using namespace std;

extern uint256 GetContractHash(UniValue contractCall);
static uint256 GetContractHash(const string& contractCall)
{
    UniValue attach(UniValue::VOBJ);
    CAttachInfo mainAttach;
    if(mainAttach.read(contractCall) && !mainAttach.isNull())
    {
        attach = mainAttach.getTypeObj(CAttachInfo::ATTACH_CONTRACT);
        return GetContractHash(attach);
    }
    else
    {
        if (attach.read(contractCall))
        {
            if (attach.exists("version"))
            {
                int attachVersion = find_value(attach, "version").get_int();
                if (attachVersion == 2 && attach["list"].size() == 1)
                    attach = attach["list"][0];
            }

            return GetContractHash(attach);
        }
    }

    return uint256();
}

bool CreateContractTx(string& strRawTx, const UniValue& params)
{
    // check params
    if(!params.exists("contract_params"))
        return error("Missing contract params");

    if(!params.exists("symbol"))
        return error("Missing symbol");

    if(!params.exists("vin") || !params["vin"].isArray() || params["vin"].empty())
        return error("Invalid vin, vin must be an array");

    if(!params.exists("vout") || params["vout"].empty())
        return error("Missing vout");

    const UniValue& contractParams = params["contract_params"].get_array();

    // parse contract params
    const UniValue& contractRequest = contractParams[0].get_obj();
    if(!contractRequest.exists("address"))
        return error("Missing address in contract request");
    if(!contractRequest.exists("feeBackAddr"))
        return error("Missing feeBackAddr in contract request");
    if(!contractRequest.exists("params"))
        return error("Missing params in contract request");

    const string& strContractAddr = contractRequest["address"].get_str();
    const string& strFeeBackAddr = contractRequest["feeBackAddr"].get_str();
    const UniValue& callFuncParams = contractRequest["params"].get_obj();

    bool isCreate = false;
    if (contractRequest["address"].empty() && contractParams.size() == 2)
        isCreate = true;

    CChainParams::Base58Type base58Type;
    string strPubKey = "";
    string strSourceType = "";
    string strCode = "";
    string strSig = "";
    string strFunc = "";
    CContractAddress contractAddr;

    if(isCreate)
    {
        // create contract
        const UniValue& contractInfo = contractParams[1].get_obj();
        if(!contractInfo.exists("base58Type"))
            return error("Missing base58Type in contract information");
        if(!contractInfo.exists("owner_privkey"))
            return error("Missing owner_privkey in contract information");
        if(!contractInfo.exists("sourceType"))
            return error("Missing sourceType in contract information");
        if(!contractInfo.exists("code"))
            return error("Missing code in contract information");

        base58Type = (CChainParams::Base58Type)contractInfo["base58Type"].get_int();

        const string& strPrivKey = contractInfo["owner_privkey"].get_str();
        CBitcoinSecret vchSecret;
        vchSecret.SetString(strPrivKey);

        CKey key = vchSecret.GetKey();

        CPubKey pubkey = key.GetPubKey();
        strPubKey = HexStr(pubkey.begin(), pubkey.end());

        CKeyID owner_keyid = pubkey.GetID();

        strSourceType = contractInfo["sourceType"].get_str();

        strCode = contractInfo["code"].get_str();
        vector<unsigned char> vecCode = ParseHex(strCode);
        CContractCodeID contractID(Hash160(vecCode.begin(), vecCode.end()));

        contractAddr.Set(base58Type, owner_keyid, contractID);
        vector<unsigned char> vchContractAddress = contractAddr.GetData();
        uint256 hash = Hash(vchContractAddress.begin(), vchContractAddress.end());

        vector<unsigned char> vchSig;
        key.Sign(hash, vchSig);
        strSig = HexStr(vchSig);

        strFunc = "init";
    }
    else
    {
        // call contract
        if(!contractRequest.exists("function"))
            return error("Missing function in contract request");

        contractAddr = CContractAddress(contractRequest["address"].get_str());
        strFunc = contractRequest["function"].get_str();
    }

    // build attach info
    string strAttach = "";
    {
        UniValue contract(UniValue::VOBJ);
        if(isCreate)
        {
            contract.push_back(Pair("contractType", Params().Base58Prefix(base58Type)[0]));
            contract.push_back(Pair("pubKey", strPubKey));
            contract.push_back(Pair("sourceType", strSourceType));
            contract.push_back(Pair("code", strCode));
            contract.push_back(Pair("addressSign", strSig));
        }

        UniValue request(UniValue::VOBJ);
        if(!isCreate)
            request.push_back(Pair("contractAddress", strContractAddr));

        request.push_back(Pair("function", strFunc));
        request.push_back(Pair("params", callFuncParams));
        request.push_back(Pair("feeBackAddr", strFeeBackAddr));

        UniValue attach(UniValue::VOBJ);
        if(!contract.empty())
            attach.push_back(Pair("contract", contract));
        attach.push_back(Pair("request", request));
        attach.push_back(Pair("version", CONTRACT_VERSION));

        CAttachInfo attachInfo;
        attachInfo.addAttach(CAttachInfo::ATTACH_CONTRACT, attach);

        strAttach = attachInfo.write();
    }


    // calc scriptPubkey of contract
    CScript contractScriptPubKey;
    {
        CKeyID keyID;
        contractAddr.GetKeyID(keyID);

        CContractCodeID contractID;
        contractAddr.GetContractID(contractID);

        CContractTXScript contractTxScript(GetContractHash(strAttach), (CChainParams::Base58Type)contractAddr.GetBase58prefix(), keyID, contractID);
        contractScriptPubKey = GetScriptForDestination(contractTxScript);
    }

    // build transaction
    CMutableTransaction mtx;
    mtx.strAttach = strAttach;

    BuildTx(mtx, params);

    // modify vout
    for(unsigned int i = 0; i < mtx.vout.size(); i++)
    {
        CTxOut& txout = mtx.vout[i];
        if(txout.scriptPubKey == CScript())
        {
            if(mtx.gasToken.vout.empty()) // non gasToken, this out must be contract output
                txout.scriptPubKey = contractScriptPubKey;
            else
            {
                if(i == 0) // first out must be contract address
                    txout.scriptPubKey = GetScriptForDestination(CBitcoinAddress(contractAddr.ToString()).Get());
                else // this out must be contract output
                    txout.scriptPubKey = contractScriptPubKey;
            }
        }
        else
        {
            break;
        }
    }

    for(unsigned int i = 0; i < mtx.gasToken.vout.size(); i++)
    {
        CTxOut& txout = mtx.gasToken.vout[i];
        if(txout.scriptPubKey == CScript())
            txout.scriptPubKey = contractScriptPubKey;
        else
            break;
    }

    // modify business type
    if(mtx.gasToken.vout.size() == 0)
        mtx.SetBusinessType(BUSINESSTYPE_SUB_CONTRACT::BUSINESSTYPE_CONTRACTCALL | BUSINESSTYPE::BUSINESSTYPE_TRANSACTION);
    else
        mtx.SetBusinessType(BUSINESSTYPE_SUB_CONTRACT::BUSINESSTYPE_CONTRACTCALL | BUSINESSTYPE::BUSINESSTYPE_TOKEN);

    // sign transaction
    if(!SignTx(mtx, params))
        return false;

    strRawTx = EncodeHexTx(mtx);
    LogPrintf("create a new contract tx: %s\n", mtx.GetHash().GetHex());
    return true;
}
