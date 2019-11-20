#include "include/ZLIBCompress.h"
#include <memory.h>

//IMPLEMENT_SINGLETON_WITHOUT_CONSTRUCT(CZLIBCompress);

CZLIBCompress::CZLIBCompress(void)
{
}


CZLIBCompress::~CZLIBCompress(void)
{
}

int CZLIBCompress::GetMaxCompSize( int nDataSize )
{
    return compressBound(nDataSize);
}

int CZLIBCompress::Compress( char *pCompressData, int *pCompDataSize, const char *pData, int nDataSize )
{
    int nRet = 0;
    uLong ulComprLen = *pCompDataSize;

    nRet = compress((Bytef*)pCompressData, &ulComprLen,(Bytef*)pData,nDataSize);

    if (nRet != Z_OK)
    {
        nRet = -101;
    }
    else
    {
        *pCompDataSize = ulComprLen;
    }

    return nRet;
}

int CZLIBCompress::Decompress( char *pDecompressData, int nDecompDataSize, const char *pData, int nDataSize )
{
    int nRet = 0;
    uLong ulUncomprLen = nDecompDataSize;

    nRet = uncompress((Bytef*)pDecompressData, &ulUncomprLen, (Bytef*)pData, nDataSize);

    if (nRet != Z_OK)
    {
        nRet = -201;
    }
    else if (ulUncomprLen != nDecompDataSize)
    {
        nRet = -202;
    }

    return nRet;
}

