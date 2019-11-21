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
#include "script/interpreter.h"
#include "utilstrencodings.h"
#include "netmessagemaker.h"

using namespace std;

enum TX_TYPE{COMMON_TX = 1, EXCHANGE_TX, PUBLISH_TX, MULTISIG_TX, CONTRACT_TX};

static CNet net;

string CreateCommonTx(const UniValue& params);

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
            //return CreateContractTx(strParams);
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

/*
string CreateContractTx(const UniValue& params)
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
*/

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
                sigdata = CombineSignatures(vScriptPubKey[i], sigdata, DataFromTransaction(tx, i));
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
    //cout << "hash: " << hashTx.GetHex() << endl;

    PushMessage(hSocket, CNetMsgMaker(PROTOCOL_VERSION).Make(SERIALIZE_TRANSACTION_NO_WITNESS, "tx", *tx));
    return hashTx.GetHex();
}

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        cout << "Program need type of tx and file" << endl;
        return -1;
    }
    int nType = atoi(argv[1]);
    string strFile(argv[2]);

    ECC_Start();

    string strRawTx = CreateRawTransaction(nType, strFile);
    cout << "raw: " << strRawTx << endl;

    strRawTx = SignRawTransaction(strRawTx, strFile);
    cout << "sign: " << strRawTx << endl;

    net.Start();

    sleep(2);
    //SendRawTransaction(strRawTx, net.hSocket);

    ECC_Stop();

    while(true){
        sleep(10);
    }

    return 0;
}
