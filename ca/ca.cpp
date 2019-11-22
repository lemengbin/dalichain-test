//#include "ca/revokedb.h"
#include "ca.h"
#include <locale.h>
#include <fstream>
#include <sstream>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>    
#include <openssl/x509v3.h>    
#include <openssl/rand.h>
#include <openssl/engine.h>
//#include "util.h"
// #include "dbwrapper.h"

#include "GlobalProfile.h"
#include <iostream>
#include <memory>

#define LogPrintf printf

extern std::string EncodeBase58(const std::vector<unsigned char>& vch);

#undef X509_NAME
typedef struct X509_name_st X509_NAME;

static time_t ASN1_GetTimeT(ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;
    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) /* two digit year */
    {
        t.tm_year = (str[i++] - '0') * 10 + (str[i++] - '0');
        if (t.tm_year < 70)
        t.tm_year += 100;
    }
    else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
    {
        t.tm_year = (str[i++] - '0') * 1000 + (str[i++] - '0') * 100 + (str[i++] - '0') * 10 + (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon = ((str[i++] - '0') * 10 + (str[i++] - '0')) - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10 + (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10 + (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10 + (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10 + (str[i++] - '0');

    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}

int HexToTen(const char *pHex)
{
    int hexNum = 0;
    for (; *pHex!=0; pHex++) {
        hexNum *= 16;
        if ((*pHex>='0') && (*pHex<='9'))
            hexNum += *pHex - '0';
        else if ((*pHex>='a') && (*pHex<='f'))
            hexNum += *pHex - 'a' + 10;
        else if ((*pHex>='A') && (*pHex<='F'))
            hexNum += *pHex-  'A' + 10;
        else
            hexNum += 0;
    }
    return hexNum;
}

bool GetName(X509_NAME *name, char *outName)
{  
    if (name == NULL) return false;

    int num = X509_NAME_entry_count(name);
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *obj;
    ASN1_STRING *str;
    char objtmp[80]={0};
    char pmbbuf[3]={0};
    int fn_nid;
    const char *objbuf;

    setlocale(LC_CTYPE, "");
    for (int i=0; i<num; i++)
    {
        unsigned int uChina[255]={0};//存放中文
        char cEnglish[64][128]={0};//存放英文
        char out[255]={0};//输出
        entry = (X509_NAME_ENTRY *)X509_NAME_get_entry(name,i);
        obj = X509_NAME_ENTRY_get_object(entry);
        str = X509_NAME_ENTRY_get_data(entry);
        fn_nid = OBJ_obj2nid(obj);
        if (fn_nid == NID_undef)
            OBJ_obj2txt(objtmp, sizeof objtmp, obj, 1);
        else {
            objbuf = OBJ_nid2sn(fn_nid);
            strcpy(objtmp,objbuf);
            //objbuf = OBJ_nid2ln(fn_nid);
        }

        BIO *bio = BIO_new(BIO_s_mem());
        BIO_set_close(bio, BIO_CLOSE); /* BIO_free() free BUF_MEM */
        ASN1_STRING_print_ex(bio,str,ASN1_STRFLGS_ESC_QUOTE );
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bio, &bptr);

        int len = bptr->length;
        char *pbuf = new char[len+1];
        memset(pbuf, 0, len+1);
        memcpy(pbuf, bptr->data, len);
        
        //检索\U位置,存入数组
        char *pdest = NULL;
        unsigned int uUlocal = 0;
        char *ptemp = pbuf;
        unsigned int j=0;

        for (j=0;;j++)//检索位置信息,分别存入英文,中文
        {
            pdest = strstr(ptemp, "\\U");
            if (pdest == NULL) {
                strncpy(cEnglish[j], ptemp, strlen(ptemp));//保存最后一段英文
                break;
            }
            uUlocal = pdest - ptemp + 1;
            strncpy(cEnglish[j], ptemp, uUlocal-1);//保存英文
            char hex[5] = {0};
            strncpy(hex, ptemp + uUlocal+1, 4);//保存中文
            int ten = HexToTen(hex);
            uChina[j] = ten;
            ptemp = ptemp + uUlocal+5;
        }

        if (bio != NULL) BIO_free(bio);
        wchar_t pwchello[2] = {0};
        for (unsigned int k=0;k<=j;k++)//包含最后一段英文
        {
            if (k > 63)//达到英文最大数量
                break;
            strcat(out, cEnglish[k]);//加入英文
            pwchello[0] = uChina[k];
            int result = wcstombs( pmbbuf, pwchello, 2);
            if (result != -1)
                strncat(out, pmbbuf, 2);//加入中文
        }

        delete[] pbuf;
        strcat(outName, objtmp);//C
        strcat(outName, "=");//=
        strcat(outName, out);
        strcat(outName, "\n");
    }

    return true;
}

std::string ConvterASN1String(ASN1_STRING *str)
{
    std::string cstr;
    unsigned int uChina[255]={0};//存放中文
    char cEnglish[64][128]={0};//存放英文
    char out[255]={0};//输出
    char pmbbuf[3]={0};
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_set_close(bio, BIO_CLOSE); /* BIO_free() free BUF_MEM */
    ASN1_STRING_print_ex(bio, str, ASN1_STRFLGS_ESC_QUOTE);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);

    int len = bptr->length;
    char *pbuf = new char[len+1];
    memset(pbuf, 0, len+1);
    memcpy(pbuf, bptr->data, len);

    char *pdest = NULL;
    unsigned int uUlocal=0;
    char *ptemp = pbuf;
    unsigned int j=0;
    for (j=0;;j++)//检索位置信息,分别存入英文,中文
    {
        pdest = strstr(ptemp,"\\U");
        if (pdest == NULL) {
            strncpy(cEnglish[j], ptemp, strlen(ptemp));//保存最后一段英文
            break;
        }
        uUlocal = pdest - ptemp + 1;
        strncpy(cEnglish[j], ptemp, uUlocal-1);//保存英文
        char hex[5] = {0};
        strncpy(hex, ptemp+uUlocal+1, 4);//保存中文
        int ten = HexToTen(hex);
        uChina[j] = ten;
        ptemp=ptemp + uUlocal+5;
    }

    if (bio != NULL) BIO_free(bio);
    wchar_t pwchello[2] = {0};
    for (unsigned int k=0; k<=j; k++)//包含最后一段英文
    {
        if (k > 63)//达到英文最大数量
            break;
        strcat(out, cEnglish[k]);
        pwchello[0] = uChina[k];
        int result = wcstombs(pmbbuf, pwchello, 2);
        if (result != -1)
            strncat(out, pmbbuf, 2);
    }
    delete[] pbuf;
    cstr = out;
    return cstr;
}

VerifyCrtChain::VerifyCrtChain():m_leaf(NULL), m_uchain(NULL), m_store(NULL)
{
}

VerifyCrtChain::~VerifyCrtChain()
{
    if(m_leaf != NULL) 
    {
        X509_free(m_leaf);
        m_leaf = NULL;
    }

    if (m_uchain != NULL)
    {
        sk_X509_pop_free(m_uchain, X509_free);
        m_uchain = NULL;
    }

    if (m_store != NULL)
    {
        X509_STORE_free(m_store);
        m_store = NULL;
    }
}

int VerifyCrtChain::Init(unsigned int blocktime, const char *cert, int certlen, const std::string delcer)
{
    int count = 0;
    BIO *in = NULL;

    //加载吊销列表db
    /*
    std::unique_ptr<CDBIterator> iter(revok_db->NewIterator());
    iter->SeekToFirst();
    while(iter->Valid())
    {
        std::pair <int ,std::string> value;
        std::string certId = "";
        iter->GetValue(value);
        iter->GetKey(certId);

        if(certId.find("obfuscate_key") != std::string::npos)
        {
            iter->Next();
            continue;
        }

        if (value.first == NOTLEAFCERT)
            vec.push_back(certId);
   
        iter->Next();
    }
    */

    m_uchain = sk_X509_new_null();

    if (certlen == 0) 
    {
        if ((in = BIO_new_file(cert, "r")) == NULL) {
            LogPrintf("[ERROR] : VerifyCrtChain init open CA bundle file error [%s]\n", cert);
            return count;
        }
    }
    else {
        if ((in = BIO_new_mem_buf((char *)cert, certlen)) == NULL) {
            LogPrintf("[ERROR] : Make Mem Bio Error\n");
            return count;
        }   
    }

    STACK_OF(X509_INFO) *inf;
    inf = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);

    //创建X509_store对象，用来存储证书、撤销列表等
    m_store = X509_STORE_new();

    // 将栈中的证书加入到 X509_STORE
    for(int i = 0; i < sk_X509_INFO_num(inf); i++) { 
        auto itmp = sk_X509_INFO_value(inf, i);
        if(itmp->x509) {
            char * pstrserno = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(itmp->x509));
            std::string stringval = pstrserno;
            OPENSSL_free(pstrserno);
            //if(find(vec.begin(), vec.end(), stringval) != vec.end())
            //    continue;
            /*
            if (stringval == delcer || IsInRevoklist(blocktime, stringval))
                continue;
            */

            int rr = X509_STORE_add_cert(m_store, itmp->x509);// 将 X509_INFO 中的 X509 用 X509_OBJECT 形式封装，压栈到 X509_STORE 的成员 objs
            //sk_X509_push(m_chain, itmp->x509);
            if(rr != 1)
                LogPrintf("[ERROR] : X509_STORE_add_cert error <%s>\n", stringval.data());
            else
                count++;
        }
    }

    if (in != NULL) BIO_free(in);
    sk_X509_INFO_pop_free(inf, X509_INFO_free);

    return count;
}

int VerifyCrtChain::VerifyCrt(const char *cert, int certlen, bool logerr)
{
    int ret = 0;
    int verret = 0;
    //X509_STORE *store=NULL;
    X509_STORE_CTX ctx ;
    if (m_leaf) {
        X509_free(m_leaf);
        m_leaf = NULL;
    }


    //创建X509_store对象，用来存储证书、撤销列表等
    //store=X509_STORE_new();

    // 载入证书
    m_leaf = LoadCert(cert, certlen, NULL, FORMAT_PEM);

    //设置验证标记 都验证那些项 X509_V_FLAG_CRL_CHECK_ALL表示全部验证
    X509_STORE_set_flags(m_store,X509_V_FLAG_CRL_CHECK_ALL);

    //初始化CTX 这个类就是所谓的上下文 该类收集完必要的信息数据 可以进行验证
    // 此处X509_STORE_CTX_init最后一个参数为NULL，表示不加载证书撤销列表CPL
    if(!X509_STORE_CTX_init(&ctx, m_store, m_leaf, m_uchain))
    {
        ret = 0;
        goto end;
    }

/*
    if(m_chain == NULL)
    {
        std::cout<<"加载证书链失败!/n"<<std::endl;
        ret = 0;
        goto end;
    }
    else
    {
        //将证书链存入CTX
        X509_STORE_CTX_trusted_stack(ctx, m_chain);
    }
*/

    //证书链式验证
    verret = X509_verify_cert(&ctx);
    if(1 == verret || ctx.error == 10)//证书过期错误已经屏蔽，因为时间必须用区块时间
        ret = 1;
    else
    {
        ret = 0;
        if (logerr)
        {
            LogPrintf("[ERROR] VerifyCrt : errorcode<%d>, errorstring<%d, %s>\n", verret, ctx.error, X509_verify_cert_error_string(ctx.error));
        }
    }

end:
    X509_STORE_CTX_cleanup(&ctx);
    return ret;
}

int VerifyCrtChain::VerifyX509(X509 *cert, bool logerr)
{
    int ret = 0;
    int verret = 0;
    //X509_STORE *store=NULL;
    X509_STORE_CTX ctx;

    //设置验证标记 都验证那些项 X509_V_FLAG_CRL_CHECK_ALL表示全部验证
    X509_STORE_set_flags(m_store,X509_V_FLAG_CRL_CHECK_ALL);

    //初始化CTX 这个类就是所谓的上下文 该类收集完必要的信息数据 可以进行验证
    // 此处X509_STORE_CTX_init最后一个参数为NULL，表示不加载证书撤销列表CPL
    if(!X509_STORE_CTX_init(&ctx, m_store, cert, m_uchain))
    {
        ret = 0;
        goto end;
    }

    //证书链式验证
    verret = X509_verify_cert(&ctx);
    if(1 == verret)
        ret = 1;
    else
    {
        ret = 0;
        if (logerr)
        {
            LogPrintf("[ERROR] VerifyX509 : errorcode<%d>, errorstring<%d, %s>\n", verret, ctx.error, X509_verify_cert_error_string(ctx.error));
        }
    }

end:
    X509_STORE_CTX_cleanup(&ctx);
    return ret;
}

bool VerifyCrtChain::InsertUchain(const char *cert, int certlen)
{
    X509 *ptmp = LoadCert(cert, certlen, NULL, FORMAT_PEM);
    if (ptmp == NULL) {    
        return false;    
    }

    sk_X509_push(m_uchain, ptmp);
    return true;
}

CCertificate::CCertificate(const char *pCertData, int nCertDataSize, int nFormat) : m_nVersion(-1)
    , m_strSerialNumber(""), m_strSubjectName(""), m_strIssuerName("")
    , m_notBefore(0), m_notAfter(0), m_isValid(false)
{
    if (Init(pCertData, nCertDataSize, nFormat) == 0)
    {
        m_vecCertContent.resize(nCertDataSize);
        m_vecCertContent.assign(pCertData, pCertData + nCertDataSize);
        m_isValid = true;
    }
}

CCertificate::CCertificate(const char *pCertPath, int nFormat) : m_nVersion(-1)
    , m_strSerialNumber(""), m_strSubjectName(""), m_strIssuerName("")
    , m_notBefore(0), m_notAfter(0), m_isValid(false)
{
    if (Init(pCertPath, 0, nFormat) == 0) 
    {
        std::ifstream in(pCertPath);
        if (in) {
            std::ostringstream ostr;
            ostr << in.rdbuf();

            std::string ss = ostr.str();
            m_vecCertContent = std::vector<unsigned char>(ss.begin(), ss.end());
            in.close();

            m_isValid = true;
            // std::cout << "ss length: " << ss.length() << endl;
            // std::cout << "m_vecCertContent GetCertBase58Str: " << GetCertBase58Str() << endl;
        }
    }
}


CCertificate::~CCertificate()
{
    // if (m_pX509 != NULL) {
    //     X509_free(m_pX509);
    //     m_pX509 = NULL;
    // }
}

int CCertificate::Init(const char *pCertFile, int nDataSize, int nFormat)
{
    X509 *pX509 = LoadCert(pCertFile, nDataSize, NULL, nFormat);
    if (pX509 == NULL) 
        return -1;

    ParseX509(pX509);
    X509_free(pX509);
    
    // std::cout << "pCertFile: " << pCertFile << endl;
    m_isValid = true;

    return 0;
}

std::string CCertificate::GetCertBase58Str() const 
{ 
    if (IsValid())
        return EncodeBase58(m_vecCertContent);
    else
        return "";
}

void CCertificate::ParseX509(X509 *pX509)
{
    if (pX509 != NULL)
    {
        // get Version
        m_nVersion = X509_get_version(pX509);
        // get SerialNumber
        m_strSerialNumber = GetCertSerialNumber(pX509);

        // get SubjectName
        char *pLine = X509_NAME_oneline(X509_get_subject_name(pX509), 0, 0);
        m_strSubjectName = pLine;
        OPENSSL_free(pLine);
        // get IssuerName
        pLine = X509_NAME_oneline(X509_get_issuer_name(pX509), 0, 0);
        m_strIssuerName = pLine;
        OPENSSL_free(pLine);

        // get notBefore
        asn1_string_st *notBefore = X509_get_notBefore(pX509);
        ASN1_UTCTIME *notBeforeDup = ASN1_STRING_dup(notBefore);
        m_notBefore = ASN1_GetTimeT(notBeforeDup);
        M_ASN1_UTCTIME_free(notBeforeDup);
        // get notAfter
        asn1_string_st *notAfter = X509_get_notBefore(pX509);
        ASN1_UTCTIME *notAfterDup = ASN1_STRING_dup(notAfter);
        m_notAfter = ASN1_GetTimeT(notAfterDup);
        M_ASN1_UTCTIME_free(notAfterDup);

        // parse Subject/Issuer
        GetCertSubject(pX509, &m_subject);
        GetCertSubject(pX509, &m_Issuer);
        // get ca PubKey
        GetCertPubKey(pX509, m_vecPubkey);
    }
}

void CCertificate::Print()
{
    std::cout << "------------------------------------" << std::endl;

    std::cout << "version: " << m_nVersion << std::endl;
    std::cout << "SerialNumber: " << m_strSerialNumber << std::endl;
    std::cout << "SubjectName: " << m_strSubjectName << std::endl;
    std::cout << "IssuerName: " << m_strIssuerName << std::endl;

    // print subject
    std::cout << "----------------" << std::endl;
    std::cout << "Print subject" << std::endl;
    std::cout << "----------------" << std::endl;
    std::cout << "C: " << m_subject.C << std::endl;
    std::cout << "ST: " << m_subject.SP << std::endl;
    std::cout << "L: " << m_subject.L << std::endl;
    std::cout << "O: " << m_subject.O << std::endl;
    std::cout << "OU: " << m_subject.OU << std::endl;
    std::cout << "CN: " << m_subject.CN << std::endl;
    // std::cout << "EMAIL: " << m_subject.EMAIL << std::endl;
    // std::cout << "PMAIL: " << m_subject.PMAIL << std::endl;
    // std::cout << "T: " << m_subject.T << std::endl;
    // std::cout << "D: " << m_subject.D << std::endl;
    // std::cout << "G: " << m_subject.G << std::endl;

    std::cout << "notBefore: " << asctime(gmtime(&m_notBefore));
    std::cout << "notAfter: " << asctime(gmtime(&m_notAfter));

    std::cout << "----------------" << std::endl;
    std::cout << "Pubkey HEX: " << std::endl;
    for (size_t i = 0; i < m_vecPubkey.size(); i++) {
        std::cout << std::hex << (int)m_vecPubkey[i];
    }
    std::cout << std::endl;

    std::cout << "------------------------------------" << std::endl;
}

CPrivateKey::CPrivateKey(const char *pKeyData, int nKeyDataSize, const char *pwd, int nFormat) : m_strPassword(""), m_isValid(false)
{
    Init(pKeyData, nKeyDataSize, pwd, nFormat);
    if (Init(pKeyData, nKeyDataSize, pwd, nFormat) == 0)
    {
        m_vecKeyContent.resize(nKeyDataSize);
        m_vecKeyContent.assign(pKeyData, pKeyData + nKeyDataSize);
        m_strPassword = pwd ? pwd : "";
        m_isValid = true;
    }
}

CPrivateKey::CPrivateKey(const char *pKeyPath, const char *pwd, int nFormat) : m_strPassword(""), m_isValid(false)
{
    if (Init(pKeyPath, 0, pwd, nFormat) == 0) 
    {
        std::ifstream in(pKeyPath);
        if (in) {
            std::ostringstream ostr;
            ostr << in.rdbuf();

            std::string ss = ostr.str();
            m_vecKeyContent = std::vector<unsigned char>(ss.begin(), ss.end());
            in.close();

            m_strPassword = pwd ? pwd : "";
            m_isValid = true;
        }
    }
}

CPrivateKey::~CPrivateKey()
{
    // if (m_pKey != NULL) {
    //     EVP_PKEY_free(m_pKey);
    //     m_pKey = NULL;
    // }
}

int CPrivateKey::Init(const char *pKeyFile, int nDataSize, const char *pwd, int nFormat)
{
    // std::cout << "pKeyFile: " << pKey << endl;
    // std::cout << "nDataSize: " << nDataSize << endl;
    // std::cout << "pwd: " << pwd << endl;
    EVP_PKEY *pKey = LoadKey(pKeyFile, nDataSize, pwd, nFormat); 
    if (pKey == NULL) 
        return -1;

    ParseKey(pKey);
    EVP_PKEY_free(pKey);
    return 0;
}

std::string CPrivateKey::GetKeyBase58Str() const 
{ 
    if (IsValid())
        return EncodeBase58(m_vecKeyContent);
    else
        return "";
}

void CPrivateKey::ParseKey(EVP_PKEY *pKey)
{
    if (pKey != NULL) {
        GetPubKey(pKey, m_vecPubkey);
        GetPrivKey(pKey, m_vecPrivkey);
    }
}

void CPrivateKey::Print()
{
    std::cout << "------------------------------------" << std::endl;

    std::cout << "----------------" << std::endl;
    std::cout << "PubKey HEX: " << std::endl;
    for (size_t i = 0; i < m_vecPubkey.size(); i++) {
        std::cout << std::hex << (int)m_vecPubkey[i];
    }
    std::cout << std::endl;

    std::cout << "----------------" << std::endl;
    std::cout << "PrivKey HEX: " << std::endl;
    for (size_t i = 0; i < m_vecPrivkey.size(); i++) {
        std::cout << std::hex << (int)m_vecPrivkey[i];
    }
    std::cout << std::endl;

    std::cout << "------------------------------------" << std::endl;
}

// 读取DER、PEM、P12文件公钥
X509* load_cert(BIO *cert, const char *pwd, int format)  
{
    X509 *x509 = NULL;
    if (format == FORMAT_DER) {
        x509 = d2i_X509_bio(cert, NULL);
    }
    else if (format == FORMAT_PEM) {
        x509 = PEM_read_bio_X509(cert, NULL, NULL, NULL);
    }
    else if (format == FORMAT_P12) {
        PKCS12 *p12 = d2i_PKCS12_bio(cert, NULL);
        PKCS12_parse(p12, pwd, NULL, &x509, NULL);
        PKCS12_free(p12);
        p12 = NULL;
    }   
    else {
        LogPrintf("[ERROR] : bad input format specified for input cert\n");
        goto end;
    }
end:
    if (x509 == NULL) {
        LogPrintf("[ERROR] : unable to load certificate\n"); 
    }

    return (x509);   
}

// 加载证书
X509* LoadCert(const char *cert, int certlen, const char *pwd, int format) 
{   
    BIO *in = NULL;
    X509 *x509 = NULL;   

    if (certlen == 0) 
    {
        if ((in = BIO_new_file(cert, "r")) == NULL) {
            LogPrintf("[ERROR] : open CA certificate file error [%s]\n", cert);
            return NULL;
        }
    }
    else {
        if ((in = BIO_new_mem_buf((char *)cert, certlen)) == NULL) {
            LogPrintf("[ERROR] : Make Mem Bio Error\n");
            return NULL;
        }   
    }

    x509 = load_cert(in, pwd, format);

    if (in != NULL) BIO_free(in);

    return x509;
}  

// 判断证书是否在吊销列表中
bool IsInRevoklist(unsigned int itime, std::string& serialno)
{
    /*
    time_t intime = itime;
    if (intime == 0)
        intime = time(NULL);

    //uint32_t revoktime;
    //std::string strRevokCrt;
    CRevokeInfo revokeInfo;
    if (getRevoke(serialno, revokeInfo)) {

        if(intime >= revokeInfo.nTime)
        {
            //std::cout << "INTIME:" << intime << " RVOKTIME:" <<  revoktime << std::endl;
            return true;
        }
    }
    */

    return false;
}

bool IsEncrypted(const char *priCert, int priCertLen)
{
    std::string prikeystr = "";
    if(priCertLen == 0)
    {
        std::ifstream inf(priCert);
        if(!inf)
            return false;
        std::ostringstream tmp;
        tmp << inf.rdbuf();
        prikeystr = tmp.str();
        inf.close();
    }
    else
    {
        prikeystr = priCert;
    }

    if(prikeystr.find("ENCRYPTED") != std::string::npos)
        return true;

    return false;
}

bool IsSupsub(const char *supcer, int suplen, const char *subcer, int sublen, unsigned int itime)
{
    time_t intime = itime;
    if (intime == 0)
        intime = time(NULL);

    if(IsLeafCert(supcer, suplen, g_strBundleCrt.data(), g_strBundleCrt.length()))
        return false;
    
    std::string supId = GetCertSerialNumber(supcer, suplen, FORMAT_PEM);
    if(supId == "" || supId == GetCertSerialNumber(subcer, sublen, FORMAT_PEM))
        return false;
    std::shared_ptr<VerifyCrtChain> verify = std::make_shared<VerifyCrtChain>();

    verify->Init(intime, g_strBundleCrt.data(), g_strBundleCrt.length(), supId);

    if(verify->VerifyCrt(subcer, sublen, false) != 1) {
        return true;
    }

    return false;
}

bool IsSupsubX509(X509 *supcer, X509 *subcer, unsigned int itime)
{
    time_t intime = itime;
    if (intime == 0)
        intime = time(NULL);

    char *supserno = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(supcer));
    std::string supId = supserno;
    
    BIO *in = NULL;
    if ((in = BIO_new_mem_buf(g_strBundleCrt.data(), g_strBundleCrt.length())) == NULL) {   
        LogPrintf("[ERROR] : Make Mem Bio Error\n");  
        OPENSSL_free(supserno);
        return false;   
    }  
    STACK_OF(X509_INFO) *inf;
    inf = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);

    BIO_free(in);

    int count = 0;
    int allsum = sk_X509_INFO_num(inf);
    for(int i = 0; i < allsum; i++) { 
        auto itmp = sk_X509_INFO_value(inf, i);
        if(itmp->x509) {
            char *bundtemp = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(itmp->x509));
            if (!strcmp(bundtemp, supserno))
            {
                OPENSSL_free(bundtemp);
                break;
            }
            OPENSSL_free(bundtemp);
        }
        count ++;
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);

    if(count == allsum) //supcert为叶子节点
        return false;
    
    char *subserno = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(subcer));
    if(supId == "" || !strcmp(supserno, subserno))
    {
        OPENSSL_free(supserno);
        OPENSSL_free(subserno);
        return false;
    }
    OPENSSL_free(supserno);
    OPENSSL_free(subserno);
    std::shared_ptr<VerifyCrtChain> verify = std::make_shared<VerifyCrtChain>();
    verify->Init(intime, g_strBundleCrt.data(), g_strBundleCrt.length(), supId);

    if(verify->VerifyX509(subcer, false) != 1) {
        return true;
    }

    return false;
}

bool IsLeafCert(const char *cert, int certlen, const char *bundle, int bundlen)
{
    X509 *x509 = LoadCert(cert, certlen, NULL, FORMAT_PEM);
    if (x509 == NULL) {
        return false;
    }
    char *inputserno = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(x509));

    BIO *in = NULL;
    bool fRet = true;
    int count = 0;
    int allsum = 0;
    STACK_OF(X509_INFO) *inf = NULL;

    if (bundlen == 0) //输入为磁盘文件    
    {   
        if ((in = BIO_new_file(bundle, "r")) == NULL) {   
            LogPrintf("[ERROR] : open bundle certificate file error\n");
            fRet =  false;
            goto __end;   
        }   
    }   
    else //输入为内存中文件    
    {   
        if ((in = BIO_new_mem_buf((char *)bundle, bundlen)) == NULL) {   
            LogPrintf("[ERROR] : Make Mem Bio Error\n");  
            fRet =  false;
            goto __end;
        }   
    }   

    inf = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    BIO_free(in);

    allsum = sk_X509_INFO_num(inf);
    for(int i = 0; i < allsum; i++) { 
        auto itmp = sk_X509_INFO_value(inf, i);
        if(itmp->x509) {
            char *bundtemp = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(itmp->x509));
            if (!strcmp(bundtemp, inputserno))
            {
                OPENSSL_free(inputserno);
                OPENSSL_free(bundtemp);
                X509_free(x509);
                if (inf != NULL)
                    sk_X509_INFO_pop_free(inf, X509_INFO_free);
                return false;
            }
            OPENSSL_free(bundtemp);
        }

        count ++;
    }

    if (inf != NULL)
        sk_X509_INFO_pop_free(inf, X509_INFO_free);

    OPENSSL_free(inputserno);
    if(count == allsum) {
        fRet =  true;
    }

__end:
    X509_free(x509);
    return fRet;
}

EVP_PKEY* load_key(BIO *bio, const char *pwd, int format) 
{   
    EVP_PKEY *pkey = NULL;   
    if (format == FORMAT_DER) {   
        pkey = d2i_PrivateKey_bio(bio, NULL);   
    }   
    else if (format == FORMAT_PEM) {   
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)pwd);   
    }   
    else if (format == FORMAT_P12) {   
        PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);   
        PKCS12_parse(p12, pwd, &pkey, NULL, NULL);   
        PKCS12_free(p12);   
        p12 = NULL;   
    }   
    else {   
        LogPrintf("[ERROR] : bad input format specified for key\n");
        goto end;   
    }   
end:   
    if (pkey == NULL)   
        LogPrintf("[ERROR] : unable to load Private Key\n");
        
    return(pkey);   
}   
   
// 获取证书的序列号
std::string GetCertSerialNumber(const char *pubCert, int pubCertLen, int certFormat)
{
    X509 *x509 = LoadCert(pubCert, pubCertLen, NULL, certFormat);
    if (x509 == NULL) {
        return "";
    }   
    char *pstrserno = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(x509));
    std::string stringval = pstrserno;
    OPENSSL_free(pstrserno);
    X509_free(x509);
    return stringval;
}

std::string GetCertSerialNumber(const X509 *pX509)
{
    std::string strSerialNumber = "";
    if (pX509 == NULL) {
        return strSerialNumber;
    }
    char *pSerialNumber = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber((X509 *)pX509));
    if (pSerialNumber) {
        strSerialNumber = pSerialNumber;
        OPENSSL_free(pSerialNumber);
    }
    
    return strSerialNumber;
}

// 获取证书的主题信息（全部信息），返回主题的字符串形式
std::string GetCertSubjectString(const char *pubCert, int pubCertLen, int certFormat)
{
    X509 *x509 = LoadCert(pubCert, pubCertLen, NULL, certFormat);
    if (x509 == NULL) {
        return "";
    }
    char buf[256] = {0};
    memset(buf,0,256);
    GetName(X509_get_subject_name(x509), buf);
    X509_free(x509);
    std::string str = buf;
    return str;
}

int GetCertSubject(X509 *pX509, LPCERTSUBJECT subject)
{
    if (pX509 == NULL) {    
        return -1;    
    }

    X509_NAME *name = X509_get_subject_name(pX509);
    int num = X509_NAME_entry_count(name);
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *obj;
    ASN1_STRING *str;
    int id;

    for (int i=0; i<num; i++)
    {
        entry = (X509_NAME_ENTRY *)X509_NAME_get_entry(name, i);
        obj = X509_NAME_ENTRY_get_object(entry);
        str = X509_NAME_ENTRY_get_data(entry);
        id = OBJ_obj2nid(obj);

        switch (id)
        {
        case NID_countryName:
            strcpy(subject->C, ConvterASN1String(str).c_str());
        case NID_commonName:
            strcpy(subject->CN, ConvterASN1String(str).c_str());
            break;
        case NID_stateOrProvinceName:
            strcpy(subject->SP, ConvterASN1String(str).c_str());
            break;
        case NID_localityName:
            strcpy(subject->L, ConvterASN1String(str).c_str());
            break;
        case NID_organizationName:
            strcpy(subject->O, ConvterASN1String(str).c_str());
            break;
        case NID_organizationalUnitName:
            strcpy(subject->OU, ConvterASN1String(str).c_str());
            break;
        case NID_pkcs9_emailAddress:
            strcpy(subject->EMAIL, ConvterASN1String(str).c_str());
            break;
        case NID_email_protect:
            strcpy(subject->PMAIL, ConvterASN1String(str).c_str());
            break;
        case NID_title:
            strcpy(subject->T, ConvterASN1String(str).c_str());
            break;
        case NID_description:
            strcpy(subject->D, ConvterASN1String(str).c_str());
            break;
        case NID_givenName:
            strcpy(subject->G, ConvterASN1String(str).c_str());
            break;
        }
    }

    return num;
}

// 获取证书的主题信息
int GetCertSubject(const char *pubCert, int pubCertLen, int certFormat, LPCERTSUBJECT subject)
{
    X509 *pX509 = LoadCert(pubCert, pubCertLen, NULL, certFormat);
    if (pX509 == NULL) 
        return -1;    

    int num = GetCertSubject(pX509, subject);
    X509_free(pX509);
    return num;
}

// 获取证书的颁发者的主题信息
int GetCertIssuer(X509 *pX509, LPCERTSUBJECT issuer)
{
    if (pX509 == NULL) 
        return -1;

    X509_NAME *name = X509_get_issuer_name(pX509);
    int num = X509_NAME_entry_count(name);
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *obj;
    ASN1_STRING *str;

    int fn_nid;
    for (int i=0; i<num; i++)
    {
        entry = (X509_NAME_ENTRY *)X509_NAME_get_entry(name, i);
        obj = X509_NAME_ENTRY_get_object(entry);
        str = X509_NAME_ENTRY_get_data(entry);
        fn_nid = OBJ_obj2nid(obj);

        switch (fn_nid)
        {
        case NID_countryName:
            strcpy(issuer->C, ConvterASN1String(str).c_str());
        case NID_commonName:
            strcpy(issuer->CN, ConvterASN1String(str).c_str());
            break;
        case NID_stateOrProvinceName:
            strcpy(issuer->SP, ConvterASN1String(str).c_str());
            break;
        case NID_localityName:
            strcpy(issuer->L, ConvterASN1String(str).c_str());
            break;
        case NID_organizationName:
            strcpy(issuer->O, ConvterASN1String(str).c_str());
            break;
        case NID_organizationalUnitName:
            strcpy(issuer->OU, ConvterASN1String(str).c_str());
            break;
        case NID_pkcs9_emailAddress:
            strcpy(issuer->EMAIL, ConvterASN1String(str).c_str());
            break;
        case NID_email_protect:
            strcpy(issuer->PMAIL, ConvterASN1String(str).c_str());
            break;
        case NID_title:
            strcpy(issuer->T, ConvterASN1String(str).c_str());
            break;
        case NID_description:
            strcpy(issuer->D, ConvterASN1String(str).c_str());
            break;
        case NID_givenName:
            strcpy(issuer->G, ConvterASN1String(str).c_str());
            break;
        }
    }

    return num;
}


// 获取证书的颁发者的主题信息
int GetCertIssuer(const char *pubCert, int pubCertLen, int certFormat, LPCERTSUBJECT subject)
{
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *obj;
    ASN1_STRING *str;
    X509 *x509 = LoadCert(pubCert, pubCertLen, NULL, certFormat);
    if (x509 == NULL) {    
        return -1;    
    }   
    X509_NAME *name = X509_get_issuer_name(x509);
    int num = X509_NAME_entry_count(name);

    int fn_nid;
    for (int i=0; i<num; i++)
    {
        entry = (X509_NAME_ENTRY *)X509_NAME_get_entry(name, i);
        obj = X509_NAME_ENTRY_get_object(entry);
        str = X509_NAME_ENTRY_get_data(entry);
        fn_nid = OBJ_obj2nid(obj);

        switch (fn_nid)
        {
        case NID_commonName:
            strcpy(subject->CN, ConvterASN1String(str).c_str());
            break;
        case NID_stateOrProvinceName:
            strcpy(subject->SP, ConvterASN1String(str).c_str());
            break;
        case NID_localityName:
            strcpy(subject->L, ConvterASN1String(str).c_str());
            break;
        case NID_organizationName:
            strcpy(subject->O, ConvterASN1String(str).c_str());
            break;
        case NID_organizationalUnitName:
            strcpy(subject->OU, ConvterASN1String(str).c_str());
            break;
        case NID_pkcs9_emailAddress:
            strcpy(subject->EMAIL, ConvterASN1String(str).c_str());
            break;
        case NID_email_protect:
            strcpy(subject->PMAIL, ConvterASN1String(str).c_str());
            break;
        case NID_title:
            strcpy(subject->T, ConvterASN1String(str).c_str());
            break;
        case NID_description:
            strcpy(subject->D, ConvterASN1String(str).c_str());
            break;
        case NID_givenName:
            strcpy(subject->G, ConvterASN1String(str).c_str());
            break;
        }
    }
    X509_free(x509);
    return num;
}

// 加载私钥
EVP_PKEY* LoadKey(const char *key, int keylen, const char *pwd, int format)   
{   
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL;
    if (keylen == 0) //输入为磁盘文件  
    {   
        if ((in = BIO_new_file(key, "r")) == NULL) {
            LogPrintf("[ERROR] : open CA certificate file error [%s]\n", key);
            return NULL;   
        }   
    }   
    else //输入为内存中文件    
    {   
        if ((in = BIO_new_mem_buf((char *)key, keylen)) == NULL) {
            LogPrintf("[ERROR] : Make Mem Bio Error\n");  
            return NULL;   
        }   
    }   
   
    pkey = load_key(in, pwd, format);
    if (in != NULL) BIO_free(in);   

    return pkey;   
}

// 检查证书有效期,在有效期内返回真，否则返回假
bool CheckCertLife(const char *pubCert, int pubCertLen, int certFormat, time_t ct)
{
    //convert to UTC time
    struct tm *ptm = gmtime(&ct);

    X509 *x509 = LoadCert(pubCert, pubCertLen, NULL, certFormat);
    if (x509 == NULL) {
        return false;
    }
    asn1_string_st *before = X509_get_notBefore(x509),
    *after = X509_get_notAfter(x509);
    ASN1_UTCTIME *be = ASN1_STRING_dup(before),
    *af = ASN1_STRING_dup(after);

    bool bf;
    //if (ASN1_UTCTIME_cmp_time_t(be,ct) >= 0 || ASN1_UTCTIME_cmp_time_t(af, ct) <= 0)
    //if(ASN1_GetTimeT(be) > ct || ASN1_GetTimeT(af) < ct)
    if(ASN1_GetTimeT(be) > mktime(ptm) || ASN1_GetTimeT(af) < mktime(ptm))
        bf = false;
    else
        bf = true;
    M_ASN1_UTCTIME_free(be);
    M_ASN1_UTCTIME_free(af);
    X509_free(x509);
    return bf;
}

// 通过根证书验证证书
bool CheckCertWithRoot(const char *pubCert, int pubCertLen, int certFormat, const char *rootCert, int rootCertLen, int rootFormat)
{
    OpenSSL_add_all_algorithms();

    X509 *x509 = LoadCert(pubCert, pubCertLen, NULL, certFormat);
    X509 *root = LoadCert(rootCert, rootCertLen, NULL, rootFormat);
    bool fRet = true;
    int ret = 0;
    EVP_PKEY *pcert = NULL;

    if (x509 == NULL || root == NULL) {
        fRet =  false;
        goto __end;
    }

    pcert = X509_get_pubkey(root);
    ret = X509_verify(x509, pcert);
    EVP_PKEY_free(pcert);

    if (ret == 1) {
        fRet = true;
    } else {
        fRet = false;
    }

__end:
    X509_free(x509);
    X509_free(root);
    return fRet;

}

// 判断父证书是否为挖矿证书
bool IsIssuerMiner(const char *supcer, int suplen)
{
    CERTSUBJECT subject;
    GetCertIssuer(supcer, suplen, FORMAT_PEM, &subject);
    std::string strCertOU = subject.OU;
    if(strCertOU.find("root") != std::string::npos)
        return true;
    if(strCertOU.find_last_of('@') == std::string::npos)
        return false;
    std::string strCertType = strCertOU.substr(strCertOU.find_last_of('@') + 1, strCertOU.length() - 1);
    if(!strcmp(strCertType.data(), CER_MINER))
    {
        return true;
    }

    return false;
}

// 数字签名
bool CASign(const char *priCert, int priCertLen, int format, const char *pwd, unsigned char *input,
          long inputLen, unsigned char *output, unsigned int *outputLen)
{
    EVP_MD_CTX md_ctx;
    EVP_PKEY *evpKey = NULL;
    //OpenSSL_add_all_digests();
    bool fRet = false;
    
    if (!strcmp(pwd, ""))
    {
        if(IsEncrypted(priCert, priCertLen))
        {
            LogPrintf("[ERROR] : No prikey password in config\n");
            return false;
        }
        evpKey = LoadKey(priCert, priCertLen, NULL, format);
    }
    else
    {
        evpKey = LoadKey(priCert, priCertLen, pwd, format);
    }
        
    if (evpKey == NULL) {    
        return false;    
    }    
    if (!EVP_SignInit(&md_ctx, EVP_sha1())) 
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_SignInit err\n"); 
        LogPrintf("[ERROR] : EVP_SignInit err\n");
        fRet = false; 
        goto __end;
    } 
    if (!EVP_SignUpdate(&md_ctx, input, inputLen))
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_SignUpdate err\n"); 
        LogPrintf("[ERROR] : EVP_SignUpdate err\n");
        fRet = false; 
        goto __end;
    } 
    if (!EVP_SignFinal(&md_ctx, (unsigned char*)output, outputLen, evpKey))
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_SignFinal err \n"); 
        LogPrintf("[ERROR] : EVP_SignFinal err\n");
        fRet = false; 
        goto __end;
    } 

    fRet = true;
__end:
    EVP_MD_CTX_cleanup(&md_ctx);

    EVP_PKEY_free(evpKey);
    return fRet;
}

// 签名验证
bool CAVerify(const char *pubCert, int pubCertLen, int format,
            const char *input, unsigned int inputLen, unsigned char *sign, unsigned int signLen)
{
    bool fRet = false;

    //OpenSSL_add_all_digests();
    X509 *x509 = LoadCert(pubCert, pubCertLen, NULL, format);
    if (x509 == NULL) {    
        return false;    
    }   

    EVP_PKEY *evpKey = X509_get_pubkey(x509);
    EVP_MD_CTX md_ctx;
    if (!EVP_VerifyInit(&md_ctx, EVP_sha1())) 
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_VerifyInit err\n"); 
        LogPrintf("[ERROR] : EVP_VerifyInit err\n");
        fRet = false;
        goto __end;
    } 
    if (!EVP_VerifyUpdate(&md_ctx, input, inputLen))
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_VerifyUpdate err\n"); 
        LogPrintf("[ERROR] : EVP_VerifyUpdate err\n");
        fRet =  false;
        goto __end;
    } 
    if (!EVP_VerifyFinal(&md_ctx, sign, signLen, evpKey))
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_VerifyFinal err \n"); 
        LogPrintf("[ERROR] : EVP_VerifyFinal err\n");
        fRet = false; 
        goto __end;
    } 

    fRet = true;

__end:
    EVP_MD_CTX_cleanup(&md_ctx);

    EVP_PKEY_free (evpKey);
    X509_free(x509);

    return fRet;
}

int GetPrivKey(EVP_PKEY *pEvpKey, std::vector<unsigned char> &vecPrivKey)
{
    if (pEvpKey == NULL)
        return -1;
    
    int nKeyLen = i2d_PrivateKey(pEvpKey, NULL);
    if (nKeyLen <= 0) {
        return -2;
    }

    vecPrivKey.resize(nKeyLen);
    unsigned char *pPrivKey = (unsigned char *)(&vecPrivKey[0]);
    i2d_PrivateKey(pEvpKey, &pPrivKey);
    return 0;
}

int GetPubKey(EVP_PKEY *pEvpKey, std::vector<unsigned char> &vecPubKey)
{
    if (pEvpKey == NULL)
        return -1;
    
    int nKeyLen = i2d_PublicKey(pEvpKey, NULL);
    if (nKeyLen <= 0) {
        return -2;
    }

    vecPubKey.resize(nKeyLen);
    unsigned char *pPubKey = (unsigned char *)(&vecPubKey[0]);
    i2d_PublicKey(pEvpKey, &pPubKey);
    return 0;
}

int GetCertPubKey(X509 *pCert, std::vector<unsigned char> &vecPubKey)
{
    EVP_PKEY *pEvpKey = X509_get_pubkey(pCert);
    if (pEvpKey == NULL)
        return -1;
    
    if (GetPubKey(pEvpKey, vecPubKey) != 0) {
        EVP_PKEY_free(pEvpKey);
        return -2;
    }
    EVP_PKEY_free(pEvpKey);
    return 0;
}


