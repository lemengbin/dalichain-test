#include <iostream>
#include <fstream>

#include "net.h"
#include "amount.h"
#include "base58.h"
#include "univalue.h"
#include "streams.h"
#include "core_io.h"
#include "transaction.h"
#include "key.h"
#include "pubkey.h"
#include "keystore.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "script/interpreter.h"
#include "utilstrencodings.h"
#include "netmessagemaker.h"
#include "ca/camempool.h"
#include "attachinfo.h"

using namespace std;

enum TX_TYPE{COMMON_TX = 1, EXCHANGE_TX, PUBLISH_TX, MULTISIG_TX, CONTRACT_TX};

static CNet net;

string CreateCommonTx(const UniValue& params);
string CreateContractTx(const UniValue& params);

UniValue ParseJsonFile(const string& strFile)
{
    ifstream file(strFile);

    stringstream buff;
    buff << file.rdbuf();
    string strContent(buff.str());

    UniValue params;
    params.read(strContent.data());

    return params;
}

string CreateRawTransaction(const int& nType, const string& strFile)
{
    UniValue params = ParseJsonFile(strFile);

    switch(nType)
    {
        case TX_TYPE::COMMON_TX:
            return CreateCommonTx(params);
        case TX_TYPE::EXCHANGE_TX:
            //return CreateExchangeTx(strParams);
        case TX_TYPE::PUBLISH_TX:
            //return CreatePublishTx(strParams);
        case TX_TYPE::MULTISIG_TX:
            //return CreateMultiSigTx(strParams);
        case TX_TYPE::CONTRACT_TX:
            return CreateContractTx(params);
            break;
    }
    return "";
}

string CreateCommonTx(const UniValue& params)
{
    string strCurrencySymbol = params["currency_symbol"].get_str();
    UniValue inputs = params["vin"].get_array();
    UniValue sendTo = params["vout"].get_obj();

    CMutableTransaction rawTx;
    rawTx.strPayCurrencySymbol = strCurrencySymbol;

    for(unsigned int i = 0; i < inputs.size(); i++)
    {
        const UniValue& input = inputs[i];
        const UniValue& o = input.get_obj();
        uint256 txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max();
        rawTx.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    vector<string> vAddress = sendTo.getKeys();
    for(const string& strKey : vAddress)
    {
        CBitcoinAddress address(strKey);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[strKey], strCurrencySymbol);
        rawTx.vout.push_back(CTxOut(nAmount, scriptPubKey));
    }

    return EncodeHexTx(rawTx);
}

extern uint256 GetContractHash(UniValue contractCall);
uint256 GetContractHash(const std::string& contractCall)
{
    UniValue attach(UniValue::VOBJ);
    CAttachInfo mainattach;
    std::cout << "contractCall: " << contractCall << std::endl;
    if(mainattach.read(contractCall) && !mainattach.isNull()) {
        attach = mainattach.getTypeObj(CAttachInfo::ATTACH_CONTRACT);
        std::cout << "!!! " << attach.write() << std::endl;
        return GetContractHash(attach);
    } else {
        if (attach.read(contractCall)) {
            if (attach.exists("version")) {
                int attachVersion = find_value(attach, "version").get_int();
                if (attachVersion == 2 && attach["list"].size() == 1) {
                    attach = attach["list"][0];
                }
            }

            std::cout << "@@@ " << attach.write() << std::endl;
            return GetContractHash(attach);
        }
    }

    return uint256();
}

#define CONTRACT_VERSION    1
string CreateContractTx(const UniValue& params)
{
    string strCurrencySymbol = params["currency_symbol"].get_str();
    UniValue contract_params = params["contract_params"].get_array();
    UniValue inputs = params["vin"].get_array();
    UniValue sendTo = params["vout"].get_obj();

    // 1. parse contract params
    UniValue contract_request = contract_params[0].get_obj();

    string strContractAddr = contract_request["address"].get_str();
    string strFeeBackAddr = contract_request["feeBackAddr"].get_str();
    UniValue callParams = contract_request["params"].get_obj();

    bool isCreate = false;
    if (contract_request["address"].empty() && contract_params.size() == 2)
        isCreate = true;

    CChainParams::Base58Type base58Type;
    string strPrivKey = "";
    string strPubKey = "";
    string strSourceType = "";
    string strCode = "";
    string strSig = "";

    CContractAddress contractAddr;
    string strFunc = "";

    if(isCreate)
    {
        // create contract
        UniValue contract_info = contract_params[1].get_obj();
        base58Type = (CChainParams::Base58Type)contract_info["base58Type"].get_int();

        strPrivKey = contract_info["owner_privkey"].get_str();
        CBitcoinSecret vchSecret;
        vchSecret.SetString(strPrivKey);

        CKey key = vchSecret.GetKey();

        CPubKey pubkey = key.GetPubKey();
        strPubKey = HexStr(pubkey.begin(), pubkey.end());

        CKeyID owner_keyid = pubkey.GetID();

        strSourceType = contract_info["sourceType"].get_str();

        strCode = contract_info["code"].get_str();
        std::vector<unsigned char> vecCode = ParseHex(strCode);
        CContractCodeID contractID(Hash160(vecCode.begin(), vecCode.end()));

        contractAddr.Set(base58Type, owner_keyid, contractID);
        std::vector<unsigned char> vchContractAddress = contractAddr.GetData();
        uint256 hash = Hash(vchContractAddress.begin(), vchContractAddress.end());

        vector<unsigned char> vchSig;
        key.Sign(hash, vchSig);
        strSig = HexStr(vchSig);
    }
    else
    {
        // call contract abi
        contractAddr = CContractAddress(contract_request["address"].get_str());
        strFunc = contract_request["function"].get_str();
    }

    CMutableTransaction rawTx;
    rawTx.strPayCurrencySymbol = strCurrencySymbol;
    rawTx.nBusinessType = BUSINESSTYPE_SUB_CONTRACT::BUSINESSTYPE_CONTRACTCALL | BUSINESSTYPE::BUSINESSTYPE_TRANSACTION;

    for(unsigned int i = 0; i < inputs.size(); i++)
    {
        const UniValue& input = inputs[i];
        const UniValue& o = input.get_obj();
        uint256 txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max();
        rawTx.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    string strAttach = "";
    {
        UniValue contract(UniValue::VOBJ);
        if(isCreate)
        {
            strFunc = "init";
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
        request.push_back(Pair("params", callParams));
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

    vector<string> vAddress = sendTo.getKeys();
    for(const string& strKey : vAddress)
    {
        CAmount nAmount = AmountFromValue(sendTo[strKey], strCurrencySymbol);
        CScript scriptPubKey;
        if(strKey == "contract")
        {
            CKeyID keyID;
            contractAddr.GetKeyID(keyID);

            CContractCodeID contractID;
            contractAddr.GetContractID(contractID);

            cout << "attach: " << strAttach << endl;
            cout << "000: " << GetContractHash(strAttach).GetHex() << endl;
            cout << "111: " << (CChainParams::Base58Type)contractAddr.GetBase58prefix() << endl;
            cout << "222: " << HexStr(keyID) << endl;
            cout << "333: " << HexStr(contractID) << endl;

            CContractTXScript contractTxScript(GetContractHash(strAttach), (CChainParams::Base58Type)contractAddr.GetBase58prefix(), keyID, contractID);
            scriptPubKey = GetScriptForDestination(contractTxScript);
            cout << "scriptPubKey: " << HexStr(scriptPubKey) << endl;
            rawTx.vout.insert(rawTx.vout.begin(), CTxOut(nAmount, scriptPubKey));
        }
        else
        {
            scriptPubKey = GetScriptForDestination(CBitcoinAddress(strKey).Get());
            rawTx.vout.push_back(CTxOut(nAmount, scriptPubKey));
        }
    }
    rawTx.strAttach = strAttach;

    return EncodeHexTx(rawTx);
}

string SignRawTransaction(const string& strRawTx, const string& strFile)
{
    vector<CMutableTransaction> txVariants;
    vector<unsigned char> txData(ParseHex(strRawTx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    while(!ssData.empty())
    {
        try{
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }catch(const std::exception&){
            throw std::ios_base::failure("SignRawTransaction: Tx decode failed");
        }
    }

    if(txVariants.empty())
        throw std::ios_base::failure("Missing transaction");

    UniValue params = ParseJsonFile(strFile);
    UniValue inputs = params["vin"].get_array();

    vector<CKey> vKey;
    vector<CScript> vScriptPubKey;
    for(unsigned int i = 0; i < inputs.size(); i++)
    {
        const UniValue& input = inputs[i];
        const UniValue& o = input.get_obj();

        CBitcoinSecret vchSecret;
        if(!vchSecret.SetString(o["privkey"].get_str()))
            throw std::ios_base::failure("Invalid private key");
        vKey.push_back(vchSecret.GetKey());

        vector<unsigned char> buf(ParseHex(o["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vScriptPubKey.push_back(scriptPubKey);
    }

    CMutableTransaction mergedTx(txVariants[0]);
    const CTransaction txConst(mergedTx);
    for(unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vKey[i]);
        ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mergedTx, i, EnumTx::TX_TOKEN, 0), vScriptPubKey[i], sigdata);
        for(const CMutableTransaction& tx : txVariants)
        {
            if(tx.vin.size() > i)
                sigdata = CombineSignatures(vScriptPubKey[i], TransactionSignatureChecker(&txConst, i, EnumTx::TX_TOKEN, 0), sigdata, DataFromTransaction(tx, i));
        }
        UpdateTransaction(mergedTx, i, sigdata);
    }
    return EncodeHexTx(mergedTx);
}

string SendRawTransaction(const string& strRawTx, int& hSocket)
{
    vector<unsigned char> txData(ParseHex(strRawTx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);

    CMutableTransaction mtx;
    try{
        ssData >> mtx;
        if(!ssData.empty())
            return "";
    }catch(const std::exception&){
        throw std::ios_base::failure("SendRawTransaction: Tx decode failed");
    }

    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    const uint256& hashTx = tx->GetHash();

    PushMessage(hSocket, CNetMsgMaker(PROTOCOL_VERSION).Make(SERIALIZE_TRANSACTION_NO_WITNESS, "tx", *tx));
    return hashTx.GetHex();
}

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        LogPrintf("Program need type of tx and file");
        return -1;
    }
    int nType = atoi(argv[1]);
    string strFile(argv[2]);

    ECC_Start();

    string strRawTx = CreateRawTransaction(nType, strFile);
    LogPrintf("raw: %s\n", strRawTx);

    /*
    strRawTx = SignRawTransaction(strRawTx, strFile);
    LogPrintf("sign: %s\n", strRawTx);

    net.Start();

    sleep(2);
    SendRawTransaction(strRawTx, net.hSocket);
    */

    ECC_Stop();

    int i = 0;
    while(i <= 5){
        sleep(1);
    }

    return 0;
}
