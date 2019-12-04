#include "construct_tx.h"
#include "base58.h"
#include "key.h"
#include "pubkey.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sign.h"
#include "core_io.h"
#include "utilstrencodings.h"

using namespace std;

bool CreateMultiSigTx(string& strRawTx, const UniValue& params)
{
    // check multisig params
    if(!params.exists("multisig_params"))
        return error("Missing multisig params");

    const UniValue& multisigParams = params["multisig_params"].get_obj();
    if(!multisigParams.exists("nrequired"))
        return error("Missing nrequired in multisig_params");
    if(!multisigParams.exists("redeemScript"))
        return error("Missing redeemScript in multisig_params");

    // get privkeys
    vector<CKey> vKey;
    int nRequired = multisigParams["nrequired"].get_int();
    for(int i = 0; i < nRequired; i++)
    {
        string strKey = "privkey_" + to_string(i + 1);
        if(!multisigParams.exists(strKey))
            return error("Missing %s in multisig_params", strKey);

        CBitcoinSecret vchSecret;
        vchSecret.SetString(multisigParams[strKey].get_str());
        vKey.push_back(vchSecret.GetKey());
    }

    // get redeemScript
    vector<unsigned char> vchRedeem(ParseHex(multisigParams["redeemScript"].get_str()));
    CScript redeemScript(vchRedeem.begin(), vchRedeem.end());

    // build transaction
    CMutableTransaction mtx;
    if(!BuildTx(mtx, params))
        return false;

    // prepare for sign
    vector<CScript> vScriptPubKey;
    UniValue vin = params["vin"].get_array();
    for(unsigned int i = 0; i < vin.size(); i++)
    {
        const UniValue& txin = vin[i].get_obj();
        if(!txin.exists("scriptPubKey"))
            return error("Missing scriptPubKey in vin[%d]", i);

        vector<unsigned char> buf(ParseHex(txin["scriptPubKey"].get_str()));
        CScript scriptPubKey(buf.begin(), buf.end());
        vScriptPubKey.push_back(scriptPubKey);
    }

    vector<CScript> vGasScriptPubKey;
    if(mtx.gasToken.vin.size() > 0)
    {
        UniValue gasVin = params["gas_vin"].get_array();
        for(unsigned int i = 0; i < gasVin.size(); i++)
        {
            const UniValue& txin = gasVin[i].get_obj();
            if(!txin.exists("scriptPubKey"))
                return error("Missing scriptPubKey in vin[%d]", i);

            vector<unsigned char> buf(ParseHex(txin["scriptPubKey"].get_str()));
            CScript scriptPubKey(buf.begin(), buf.end());
            vGasScriptPubKey.push_back(scriptPubKey);
        }
    }

    // sign transaction
    for(int m = 0; m < nRequired; m++)
    {
        CBasicKeyStore keystore;
        keystore.AddKey(vKey[m]);
        keystore.AddCScript(redeemScript);
        keystore.AddCScript(GetScriptForWitness(redeemScript));

        const CTransaction txConst(mtx);

        // sign for vin
        for(unsigned int i = 0; i < txConst.vin.size(); i++)
        {
            SignatureData sigdata;
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mtx, i, EnumTx::TX_TOKEN, 0), vScriptPubKey[i], sigdata);
            sigdata = CombineSignatures(vScriptPubKey[i], TransactionSignatureChecker(&txConst, i, EnumTx::TX_TOKEN, 0), sigdata, DataFromTransaction(mtx, i));
            UpdateTransaction(mtx, i, sigdata);
        }

        // sign for gas vin
        for(unsigned int i = 0; i < txConst.gasToken.vin.size(); i++)
        {
            SignatureData sigdata;
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mtx, i, EnumTx::TX_GAS, 0), vGasScriptPubKey[i], sigdata);
            sigdata = CombineSignatures(vGasScriptPubKey[i], TransactionSignatureChecker(&txConst, i, EnumTx::TX_GAS, 0), sigdata, GasDataFromTransaction(mtx, i));
            UpdateGasTransaction(mtx, i, sigdata);
        }
    }

    strRawTx = EncodeHexTx(mtx);
    LogPrintf("create a new multisig tx: %s\n", mtx.GetHash().GetHex());
    return true;
}
