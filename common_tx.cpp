#include "construct_tx.h"
#include "core_io.h"

using namespace std;

bool CreateCommonTx(string& strRawTx, const UniValue& params)
{
    CMutableTransaction mtx;
    if(!BuildTx(mtx, params) || !SignTx(mtx, params))
        return false;

    strRawTx = EncodeHexTx(mtx);
    LogPrintf("create a new common tx: %s\n", mtx.GetHash().GetHex());
    return true;
}
