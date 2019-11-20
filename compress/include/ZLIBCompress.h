/**
* @Copyright    深圳市今古科技有限公司
* @System       通用压缩基础库
* @Brief        ZLIB压缩实现基类
* @Author       xmx
* @Date         2016-06-5
* @Usage        无
* @History
*     日 期           版本           修改人                 修改内容
*     2016/06/5.      1.0            <xmx>                  <新建文档>
*
*/

#pragma once
#include "CompressAlgorithmBase.h"

#if _MSC_VER==1600 //vc++10.0
#ifdef /*WINDOWS32*/WIN32
#define ZLIB_WINAPI
#endif
#endif

#include "zlib.h"

class CZLIBCompress :
    public CCompressAlgorithmBase
{
    //DECLARE_SINGLETON_WITHOUT_CONSTRUCT(CZLIBCompress);
public:

    CZLIBCompress(void);
    ~CZLIBCompress(void);

public:

    /**
    *    获取数据压缩最大缓存大小.
    *    @param nDataSize [in]原数据大小.
    *    @return 成功则返回0，否则返回负数.
    */
    int GetMaxCompSize(int nDataSize);

    /**
    *    数据压缩.
    *    @param pCompressData [in]压缩后数据缓存(需带入最大压缩字节大小的缓存).
    *    @param pCompDataSize [in]压缩后数据大小.
    *    @param pData [in]原数据缓存.
    *    @param nDataSize [in]原数据大小.
    *    @return 成功则返回0，否则返回负数.
    */
    int Compress(char *pCompressData, int *pCompDataSize, const char *pData, int nDataSize);

    /**
    *    数据解压.
    *    @param pDecompressData [in]解缩结果数据缓存.
    *    @param nDecompDataSize [in]解缩结果数据大小.
    *    @param pData [in]原数据缓存.
    *    @param nDataSize [in]原数据大小.
    *    @return 成功则返回0，否则返回负数.
    */
    int Decompress(char *pDecompressData, int nDecompDataSize, const char *pData, int nDataSize);
};

