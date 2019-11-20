/**
* @Copyright
* @System       通用压缩基础库
* @Brief        LZ4压缩实现基类
* @Author       xmx
* @Date         2016-06-5
* @Usage        无
* @History
*    日 期           版本           修改人                 修改内容
*    2016/06/5.      1.0            <xmx>                  <新建文档>
*
*/

#pragma once
#include "CompressAlgorithmBase.h"
#include "lz4.h"
//#include "..\..\..\include\common\JG_Com_Singleton.h"

class CLZ4Compress :
    public CCompressAlgorithmBase
{
    //DECLARE_SINGLETON_WITHOUT_CONSTRUCT(CLZ4Compress);
public:

    CLZ4Compress(void);
    ~CLZ4Compress(void);

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

