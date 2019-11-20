#include "include/SnappyCompress.h"
#include <memory.h>

//IMPLEMENT_SINGLETON_WITHOUT_CONSTRUCT(CSnappyCompress);

CSnappyCompress::CSnappyCompress(void)
{
}


CSnappyCompress::~CSnappyCompress(void)
{
}

int CSnappyCompress::GetMaxCompSize( int nDataSize )
{
    return 32 + nDataSize + nDataSize/6;
}

int CSnappyCompress::Compress( char *pCompressData, int *pCompDataSize, const char *pData, int nDataSize )
{
    int nRet = -100;
    nRet = snappy_compress(pData, nDataSize, pCompressData, (size_t*)(pCompDataSize));

    if (nRet != SNAPPY_OK)
    {
        nRet = -101;
    }
    else
    {
        nRet = snappy_validate_compressed_buffer(pCompressData, *pCompDataSize);

        if (nRet != SNAPPY_OK)
        {
            *pCompDataSize = 0;
            nRet = -102;
        }
    }

    return nRet;
}

int CSnappyCompress::Decompress( char *pDecompressData, int nDecompDataSize, const char *pData, int nDataSize )
{
    int nRet = -200;

    ///解缩方法
    int nUncompressedLength = 0;
    nRet = snappy_uncompressed_length(pData, nDataSize, (size_t*)(&nUncompressedLength));

    if (nRet != SNAPPY_OK || nUncompressedLength != nDecompDataSize)
    {
        return -201;
    }
    else
    {
        nRet = snappy_uncompress(pData, nDataSize, pDecompressData,(size_t*)(&nDecompDataSize));

        if (nRet != SNAPPY_OK)
        {
            nRet = -202;
        }
    }

    return nRet;
}
