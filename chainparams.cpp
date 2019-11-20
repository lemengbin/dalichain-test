#include "chainparams.h"

static CChainParams *pCurrentParams = 0;

const CChainParams &Params()
{
    if(pCurrentParams == 0)
        pCurrentParams = new CChainParams();
    return *pCurrentParams;
}
