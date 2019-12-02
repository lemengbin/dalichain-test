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
#include "GlobalProfile.h"
#include "consensus/merkle.h"

using namespace std;

enum TX_TYPE{COMMON_TX = 1, EXCHANGE_TX, PUBLISH_TX, MULTISIG_TX, CONTRACT_TX};

static CNet net;

string CreateCommonTx(const UniValue& params);
string CreateContractTx(const UniValue& params);
string CreatePublishTx(const UniValue& params);
string CreateExchangeTx(const UniValue& params);

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
            return CreateExchangeTx(params);
        case TX_TYPE::PUBLISH_TX:
            return CreatePublishTx(params);
        case TX_TYPE::MULTISIG_TX:
            //return CreateMultiSigTx(params);
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
uint256 GetContractHash(const string& contractCall)
{
    UniValue attach(UniValue::VOBJ);
    CAttachInfo mainattach;
    if(mainattach.read(contractCall) && !mainattach.isNull()) {
        attach = mainattach.getTypeObj(CAttachInfo::ATTACH_CONTRACT);
        return GetContractHash(attach);
    } else {
        if (attach.read(contractCall)) {
            if (attach.exists("version")) {
                int attachVersion = find_value(attach, "version").get_int();
                if (attachVersion == 2 && attach["list"].size() == 1) {
                    attach = attach["list"][0];
                }
            }

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
        vector<unsigned char> vecCode = ParseHex(strCode);
        CContractCodeID contractID(Hash160(vecCode.begin(), vecCode.end()));

        contractAddr.Set(base58Type, owner_keyid, contractID);
        vector<unsigned char> vchContractAddress = contractAddr.GetData();
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

            CContractTXScript contractTxScript(GetContractHash(strAttach), (CChainParams::Base58Type)contractAddr.GetBase58prefix(), keyID, contractID);
            scriptPubKey = GetScriptForDestination(contractTxScript);
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

int GetWitnessCommitmentIndex(CTransactionRef& tx)
{
    int commitpos = -1;
    for (size_t o = 0; o < tx->vout.size(); o++) {
        if (tx->vout[o].scriptPubKey.size() >= 38 && tx->vout[o].scriptPubKey[0] == OP_RETURN && tx->vout[o].scriptPubKey[1] == 0x24 && tx->vout[o].scriptPubKey[2] == 0xaa && tx->vout[o].scriptPubKey[3] == 0x21 && tx->vout[o].scriptPubKey[4] == 0xa9 && tx->vout[o].scriptPubKey[5] == 0xed) {
            commitpos = o;
        }
    }
    return commitpos;
}

void UpdateUncommittedTxStructures(CTransactionRef& ptx, const Consensus::Params& consensusParams)
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

vector<unsigned char> GenerateTokenCoinbaseCommitment(CTransactionRef& ptx, const Consensus::Params& consensusParams)
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

string CreatePublishTx(const UniValue& params)
{
    UniValue gasvin = params["gasvin"].get_array();
    UniValue gasvout = params["gasvout"].get_obj();

    string strTokenParams = params["token_params"].get_str();
    vector<unsigned char> vchRet;
    DecodeBase58(strTokenParams, vchRet);
    string strTokenInfo = "";
    strTokenInfo.insert(strTokenInfo.begin(), vchRet.begin(), vchRet.end());
    UniValue tokenParams;
    tokenParams.read(strTokenInfo);

    string strTokenName = tokenParams["tokenName"].get_str();
    string strOwnerAddr = tokenParams["address"].get_str();
    CBitcoinAddress ownerAddr(strOwnerAddr);
    CAmount nMaxAmount = -1 * COIN;
    string strMaxAmount = tokenParams["maximum"].get_str();
    if(strMaxAmount.find("-") == string::npos)
        nMaxAmount = AmountFromValue(tokenParams["maximum"], strTokenName);
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

    CMutableTransaction rawTx;
    rawTx.SetBusinessType(BUSINESSTYPE_TOKEN);
    rawTx.tokenParam.nTokenType = TOKEN_CREATE;
    rawTx.vin.resize(1);
    rawTx.vin[0].prevout.SetNull();
    rawTx.vin[0].scriptSig = CScript() << 0 << OP_0;
    rawTx.vout.resize(1);
    rawTx.vout[0].scriptPubKey = GetScriptForDestination(ownerAddr.Get());
    rawTx.vout[0].nValue = nAmount;
    rawTx.strPayCurrencySymbol = strTokenName;
    rawTx.gasToken.strPayCurrencySymbol = GlobalProfile::strPayCurrencySymbol;
    rawTx.tokenParam.nValueLimit = nMaxAmount;
    rawTx.tokenParam.nAdditional = fIncrease ? TOKEN_ISSUANCE : TOKEN_NOISSUANCE;

    if(fIncrease)
    {
        if(nMaxAmount < 0)
            rawTx.vout.push_back(CTxOut(TOKEN_MAX_MONEY - nAmount, GetScriptForDestinationAppendToken(ownerAddr.Get())));
        else if(nMaxAmount > nAmount)
            rawTx.vout.push_back(CTxOut(nMaxAmount - nAmount, GetScriptForDestinationAppendToken(ownerAddr.Get())));
    }

    CAttachInfo attach;
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("hexString", strTokenParams));
    attach.addAttach(CAttachInfo::ATTACH_PUBTOKEN, obj);
    rawTx.strAttach = attach.write();

    vector<CKey> vKey;
    vector<CScript> vScriptPubKey;
    for(unsigned int i = 0; i < gasvin.size(); i++)
    {
        const UniValue& gas_input = gasvin[i];
        const UniValue& o = gas_input.get_obj();

        CBitcoinSecret vchSecret;
        if(!vchSecret.SetString(o["privkey"].get_str()))
            throw std::ios_base::failure("Invalid private key");
        vKey.push_back(vchSecret.GetKey());

        vector<unsigned char> buf(ParseHex(o["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vScriptPubKey.push_back(scriptPubKey);

        uint256 txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max() - 1;
        rawTx.gasToken.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    vector<string> vAddress = gasvout.getKeys();
    for(const string& strKey : vAddress)
    {
        CBitcoinAddress address(strKey);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(gasvout[strKey], GlobalProfile::strPayCurrencySymbol);
        rawTx.gasToken.vout.push_back(CTxOut(nAmount, scriptPubKey));
    }

    CTransactionRef tx(MakeTransactionRef(std::move(rawTx)));
    GenerateTokenCoinbaseCommitment(tx, Params().GetConsensus());

    CMutableTransaction mergedTx(*tx);
    const CTransaction txConst(mergedTx);
    for(unsigned int i = 0; i < mergedTx.gasToken.vin.size(); i++)
    {
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vKey[i]);
        ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mergedTx, i, EnumTx::TX_GAS, 0), vScriptPubKey[i], sigdata);
        if(mergedTx.gasToken.vin.size() > i)
            sigdata = CombineSignatures(vScriptPubKey[i], TransactionSignatureChecker(&txConst, i, EnumTx::TX_GAS, 0), sigdata, GasDataFromTransaction(mergedTx, i));
        UpdateGasTransaction(mergedTx, i, sigdata);
    }

    return EncodeHexTx(mergedTx);
}

string CreateExchangeTx(const UniValue& params)
{
    // 1. create txExch
    const UniValue& send_utxo = params["send_utxo"].get_obj();
    const string& strSendSymbol = send_utxo["symbol"].get_str();
    const UniValue& send_inputs = send_utxo["vin"].get_array();
    const UniValue& send_sendTo = send_utxo["vout"].get_obj();

    CMutableTransaction mtxExch;
    mtxExch.strPayCurrencySymbol = strSendSymbol;
    mtxExch.SetBusinessType(BUSINESSTYPE_TOKEN);
    mtxExch.SetExchangeType(BUSINESSTYPE_EXCHANGE | BUSINESSTYPE_EXCHANGE_END);

    vector<CKey> vSendKey;
    vector<CScript> vSendScriptPubKey;
    for(unsigned int i = 0; i < send_inputs.size(); i++)
    {
        const UniValue& input = send_inputs[i];
        const UniValue& o = input.get_obj();
        const uint256& txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max();

        CBitcoinSecret vchSecret;
        vchSecret.SetString(o["privkey"].get_str());
        vSendKey.push_back(vchSecret.GetKey());

        vector<unsigned char> buf(ParseHex(o["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vSendScriptPubKey.push_back(scriptPubKey);

        mtxExch.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    vector<string> vSendAddress = send_sendTo.getKeys();
    for(const string& strKey : vSendAddress)
    {
        CBitcoinAddress address(strKey);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(send_sendTo[strKey], strSendSymbol);
        mtxExch.vout.push_back(CTxOut(nAmount, scriptPubKey));
    }

    const string& strSendGasSymbol = send_utxo["gas_symbol"].get_str();
    const UniValue& send_gasInputs = send_utxo["gasvin"].get_array();
    const UniValue& send_gasSendTo = send_utxo["gasvout"].get_obj();

    mtxExch.gasToken.strPayCurrencySymbol = strSendGasSymbol;

    vector<CKey> vSendGasKey;
    vector<CScript> vSendGasScriptPubKey;
    for(unsigned int i = 0; i < send_gasInputs.size(); i++)
    {
        const UniValue& input = send_gasInputs[i];
        const UniValue& o = input.get_obj();
        const uint256& txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max();

        CBitcoinSecret vchSecret;
        vchSecret.SetString(o["privkey"].get_str());
        vSendGasKey.push_back(vchSecret.GetKey());

        vector<unsigned char> buf(ParseHex(o["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vSendGasScriptPubKey.push_back(scriptPubKey);

        mtxExch.gasToken.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    vector<string> vSendGasAddress = send_gasSendTo.getKeys();
    for(const string& strKey : vSendGasAddress)
    {
        CBitcoinAddress address(strKey);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(send_gasSendTo[strKey], strSendGasSymbol);
        mtxExch.gasToken.vout.push_back(CTxOut(nAmount, scriptPubKey));
    }

    // 2. create txMain
    const UniValue& recv_utxo = params["recv_utxo"].get_obj();
    const string& strRecvSymbol = recv_utxo["symbol"].get_str();
    const UniValue& recv_inputs = recv_utxo["vin"].get_array();
    const UniValue& recv_sendTo = recv_utxo["vout"].get_obj();

    CMutableTransaction mtxMain;
    mtxMain.strPayCurrencySymbol = strRecvSymbol;
    mtxMain.SetBusinessType(BUSINESSTYPE_TOKEN);
    mtxMain.SetExchangeType(BUSINESSTYPE_EXCHANGE);
    mtxMain.txExch = std::move(MakeMutableTransactionRef(mtxExch));

    vector<CKey> vRecvKey;
    vector<CScript> vRecvScriptPubKey;
    for(unsigned int i = 0; i < recv_inputs.size(); i++)
    {
        const UniValue& input = recv_inputs[i];
        const UniValue& o = input.get_obj();
        const uint256& txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max() - 1;

        CBitcoinSecret vchSecret;
        vchSecret.SetString(o["privkey"].get_str());
        vRecvKey.push_back(vchSecret.GetKey());

        vector<unsigned char> buf(ParseHex(o["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vRecvScriptPubKey.push_back(scriptPubKey);

        mtxMain.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    vector<string> vRecvAddress = recv_sendTo.getKeys();
    for(const string& strKey : vRecvAddress)
    {
        CBitcoinAddress address(strKey);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(recv_sendTo[strKey], strRecvSymbol);
        mtxMain.vout.push_back(CTxOut(nAmount, scriptPubKey));
    }

    const string& strRecvGasSymbol = recv_utxo["gas_symbol"].get_str();
    const UniValue& recv_gasInputs = recv_utxo["gasvin"].get_array();
    const UniValue& recv_gasSendTo = recv_utxo["gasvout"].get_obj();

    mtxMain.gasToken.strPayCurrencySymbol = strRecvGasSymbol;

    vector<CKey> vRecvGasKey;
    vector<CScript> vRecvGasScriptPubKey;
    for(unsigned int i = 0; i < recv_gasInputs.size(); i++)
    {
        const UniValue& input = recv_gasInputs[i];
        const UniValue& o = input.get_obj();
        const uint256& txid = uint256S(o["txid"].get_str());
        int nOuttype = o["outtype"].get_int();
        int n = o["vout"].get_int();
        int nSequence = std::numeric_limits<uint32_t>::max() - 1;

        CBitcoinSecret vchSecret;
        vchSecret.SetString(o["privkey"].get_str());
        vRecvGasKey.push_back(vchSecret.GetKey());

        vector<unsigned char> buf(ParseHex(o["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vRecvGasScriptPubKey.push_back(scriptPubKey);

        mtxMain.gasToken.vin.push_back(CTxIn(COutPoint(txid, (EnumTx)nOuttype, n), CScript(), nSequence));
    }

    vector<string> vRecvGasAddress = recv_gasSendTo.getKeys();
    for(const string& strKey : vRecvGasAddress)
    {
        CBitcoinAddress address(strKey);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(recv_gasSendTo[strKey], strRecvGasSymbol);
        mtxMain.gasToken.vout.push_back(CTxOut(nAmount, scriptPubKey));
    }

    /*
    for(unsigned int i = 0; i < mtxMain.vin.size(); i++)
    {
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vRecvKey[i]);
        ProduceSignature(DummySignatureCreator(&keystore), vRecvScriptPubKey[i], sigdata);
        UpdateTransaction(mtxMain, i, sigdata);
    }
    */

    // 2. sign txMain
    const CTransaction txMainConst(mtxMain);
    for(unsigned int i = 0; i < txMainConst.vin.size(); i++)
    {
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vRecvKey[i]);
        ProduceSignature(TransactionSignatureCreator(&keystore, &txMainConst, i, EnumTx::TX_TOKEN, 0), vRecvScriptPubKey[i], sigdata);
        UpdateTransaction(mtxMain, i, sigdata);
    }
    for(unsigned int i = 0; i < txMainConst.gasToken.vin.size(); i++)
    {
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vRecvGasKey[i]);
        ProduceSignature(TransactionSignatureCreator(&keystore, &txMainConst, i, EnumTx::TX_GAS, 0), vRecvGasScriptPubKey[i], sigdata);
        UpdateGasTransaction(mtxMain, i, sigdata);
    }

    // 3. sign txExch
    const CTransaction txMainTemp(mtxMain);
    CExchangeTransactionSignatureSerializer signTemp(txMainTemp);

    CHashWriter ss(SER_GETHASH, 0);
    ss << signTemp;
    mtxExch.theOtherHash = ss.GetHash();

    const CTransaction txExchConst(mtxExch);
    for(unsigned int i = 0; i < txExchConst.vin.size(); i++)
    {
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vSendKey[i]);
        ProduceSignature(TransactionSignatureCreator(&keystore, &txExchConst, i, EnumTx::TX_TOKEN, 0), vSendScriptPubKey[i], sigdata);
        UpdateTransaction(mtxExch, i, sigdata);
    }
    for(unsigned int i = 0; i < txExchConst.gasToken.vin.size(); i++)
    {
        SignatureData sigdata;
        CBasicKeyStore keystore;
        keystore.AddKey(vSendGasKey[i]);
        ProduceSignature(TransactionSignatureCreator(&keystore, &txExchConst, i, EnumTx::TX_GAS, 0), vSendGasScriptPubKey[i], sigdata);
        UpdateGasTransaction(mtxExch, i, sigdata);
    }

    mtxMain.txExch = std::move(MakeMutableTransactionRef(mtxExch));

    /*
    CTransaction txMainNew(mtxMain);
    cout << "union: " << txMainNew.GetHash().GetHex() << endl;
    cout << EncodeHexTx(txMainNew) << endl;

    CMutableTransaction mtxHead(txMainNew);
    CMutableTransaction mtxTail(*txMainNew.txExch);

    mtxHead.txExch = NULL;
    mtxTail.txExch = NULL;
    mtxHead.nBusinessType |= BUSINESSTYPE_EXCHANGE_SINGLE;
    mtxTail.nBusinessType |= BUSINESSTYPE_EXCHANGE_SINGLE;
    mtxHead.theOtherHash = mtxTail.GetHash();
    mtxTail.theOtherHash = mtxHead.GetHash();
    cout << "head: " << mtxHead.GetHash().GetHex() << endl;
    cout << "tail: " << mtxTail.GetHash().GetHex() << endl;
    cout << "union: " << mtxMain.GetHash().GetHex() << endl;
    cout << "union raw: " << EncodeHexTx(mtxMain) << endl;
    */

    return EncodeHexTx(mtxMain);
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

string SendRawTransaction(const string& strRawTx, int& hSocket, bool fWitness)
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

    int nFlags = fWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;
    PushMessage(hSocket, CNetMsgMaker(PROTOCOL_VERSION).Make(nFlags, "tx", *tx));
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

    if(nType != PUBLISH_TX || nType != EXCHANGE_TX)
    {
        strRawTx = SignRawTransaction(strRawTx, strFile);
        LogPrintf("sign: %s\n", strRawTx);
    }

    net.Start();

    sleep(2);
    SendRawTransaction(strRawTx, net.hSocket, nType == PUBLISH_TX);

    ECC_Stop();

    int i = 0;
    while(i++ < 5){
        sleep(1);
    }

    return 0;
}
