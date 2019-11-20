#include "include/LZ4Compress.h"
#include <memory.h>

//IMPLEMENT_SINGLETON_WITHOUT_CONSTRUCT(CLZ4Compress);

CLZ4Compress::CLZ4Compress(void)
{
}


CLZ4Compress::~CLZ4Compress(void)
{
}

int CLZ4Compress::GetMaxCompSize( int nDataSize )
{
    return LZ4_compressBound(nDataSize);
}

int CLZ4Compress::Compress( char *pCompressData, int *pCompDataSize, const char *pData, int nDataSize )
{
    *pCompDataSize = LZ4_compress((char*)pData, pCompressData, nDataSize);

    if (*pCompDataSize == 0)
    {
        return -101;
    }

    return 0;
}

int CLZ4Compress::Decompress( char *pDecompressData, int nDecompDataSize, const char *pData, int nDataSize )
{
    int nTempDecompressDataSize = LZ4_decompress_safe(pData, pDecompressData, nDataSize, nDecompDataSize);

    if (nTempDecompressDataSize != nDecompDataSize)
    {
        return -201;
    }

    return 0;
}

