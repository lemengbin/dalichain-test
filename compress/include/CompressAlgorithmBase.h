/**
* @Copyright
* @System       通用压缩基础库
* @Brief        通用压缩实现基类
* @Author       xmx
* @Date         2016-06-5
* @Usage        无
* @History
*    日 期           版本           修改人                 修改内容
*    2016/06/5.      1.0            <xmx>                  <新建文档>
*
*/


#pragma once
class CCompressAlgorithmBase
{
public:
    CCompressAlgorithmBase(void);
    virtual ~CCompressAlgorithmBase(void);

public:

    /**
    *    获取数据压缩最大缓存大小.
    *    @param nDataSize [in]原数据大小.
    *    @return 成功则返回0，否则返回负数.
    */
    virtual int GetMaxCompSize(int nDataSize) = 0;

    /**
    *    数据压缩.
    *    @param pCompressData [in]压缩后数据缓存.
    *    @param pCompDataSize [in]压缩后数据大小.
    *    @param pData [in]原数据缓存.
    *    @param nDataSize [in]原数据大小.
    *    @return 成功则返回0，否则返回负数.
   */
    virtual int Compress(char *pCompressData, int *pCompDataSize, const char *pData, int nDataSize) = 0;

    /**
    *    数据解压.
    *    @param pDecompressData [in]解缩结果数据缓存.
    *    @param nDecompDataSize [in]解缩结果数据大小.
    *    @param pData [in]原数据缓存.
    *    @param nDataSize [in]原数据大小.
    *    @return 成功则返回0，否则返回负数.
    */
    virtual int Decompress(char *pDecompressData, int nDecompDataSize, const char *pData, int nDataSize) = 0;
};

