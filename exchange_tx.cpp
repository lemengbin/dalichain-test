#include "construct_tx.h"
#include "core_io.h"

using namespace std;

static bool CreateTailTx(CMutableTransaction& mtx, const UniValue& params)
{
    if(!BuildTx(mtx, params))
        return false;

    mtx.SetExchangeType(BUSINESSTYPE_EXCHANGE | BUSINESSTYPE_EXCHANGE_END);
    return true;
}

static bool CreateHeadTx(CMutableTransaction& mtx, const UniValue& params)
{
    if(!BuildTx(mtx, params))
        return false;

    mtx.SetExchangeType(BUSINESSTYPE_EXCHANGE);
    return true;
}

bool CreateExchangeTx(string& strRawTx, const UniValue& params)
{
    if(!params.exists("send_utxo"))
        return error("Missing utxo of sender");

    if(!params.exists("recv_utxo"))
        return error("Missing utxo of receiver");

    CMutableTransaction mtxMain;
    CMutableTransaction mtxExch;

    const UniValue& send_params = params["send_utxo"].get_obj();
    const UniValue& recv_params = params["recv_utxo"].get_obj();

    // Build tail tx
    if(!CreateTailTx(mtxExch, send_params))
        return error("create tail tx of exchange tx failed");

    // Build head tx
    if(!CreateHeadTx(mtxMain, recv_params))
        return error("create head tx of exchange tx failed");
    mtxMain.txExch = std::move(MakeMutableTransactionRef(mtxExch));

    // Sign head tx
    if(!SignTx(mtxMain, recv_params))
        return error("sign head tx of exchange tx failed");

    // Sign tail tx
    if(!SignTx(mtxExch, send_params))
        return error("sign tail tx of exchange tx failed");

    // last
    mtxMain.txExch = std::move(MakeMutableTransactionRef(mtxExch));

    // split
    CTransaction txMainNew(mtxMain);
    CMutableTransaction mtxHead(txMainNew);
    CMutableTransaction mtxTail(*txMainNew.txExch);

    mtxHead.txExch = NULL;
    mtxTail.txExch = NULL;
    mtxHead.nBusinessType |= BUSINESSTYPE_EXCHANGE_SINGLE;
    mtxTail.nBusinessType |= BUSINESSTYPE_EXCHANGE_SINGLE;
    mtxHead.theOtherHash = mtxTail.GetHash();
    mtxTail.theOtherHash = mtxHead.GetHash();

    LogPrintf("create a new exchange tx, detail as below:\n");
    LogPrintf("head tx id: %s\n", mtxHead.GetHash().GetHex());
    LogPrintf("tailf tx id: %s\n", mtxTail.GetHash().GetHex());
    LogPrintf("union tx id: %s\n", mtxMain.GetHash().GetHex());

    strRawTx = EncodeHexTx(mtxMain);
    return true;
}
