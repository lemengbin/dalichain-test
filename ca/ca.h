#ifndef BITCOIN_CA_H
#define BITCOIN_CA_H

// #include "GlobalProfile.h"

#include <map>
#include <string>
#include <vector>

#ifdef WIN32
#include <winsock2.h> // Must be included before mswsock.h and windows.h
#include <mswsock.h>
#include <windows.h>
#include <winsock.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/tcp.h>
#endif

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#define FORMAT_DER 1 // FORMAT_ASN1
#define FORMAT_PEM 3
#define FORMAT_NET 4
#define FORMAT_P12 5

#define CER_ACCESS "ACCESS"
#define CER_MINER "MINER"

#define LEAFCERT 0    //叶子证书
#define NOTLEAFCERT 1 //非叶子证书

#define REVOKEINFO_VER 1

class Uncopyable
{
private:
    Uncopyable(const Uncopyable&);
    Uncopyable& operator=(const Uncopyable&);
};

// RSA硬件签名传入传出结构
typedef struct
{
    unsigned int nDataLen;
    unsigned char szData[256];
} RSA_DATA;

// 证书扩展项
typedef struct CERTEXT {
    int IOID;        //OID Value
    char OID[32];    //OID Mark
    char NAME[32];   //Extent subject name
    char VALUE[128]; //value

    CERTEXT()
    {
        memset(this, 0, sizeof(CERTEXT));
    }
} CERTEXT, *LPCERTEXT;

// 证书主题
typedef struct CERTSUBJECT {
    char CN[64];    //Common Name
    char C[16];     //Country
    char SP[20];    //stateOrProvinceName
    char ST[64];    //streetAddress
    char L[64];     //locality
    char O[64];     //Organize
    char OU[64];    //Organize Unit
    char EMAIL[64]; //Email
    char PMAIL[64]; //Protected Email
    char T[32];     //Title
    char D[32];     //Description
    char G[32];     //GivenName
    char DC[32];    //domainComponent

    CERTSUBJECT()
    {
        memset(this, 0, sizeof(CERTSUBJECT));
    }
} CERTSUBJECT, *LPCERTSUBJECT;

// 吊销证书信息
typedef struct CRLREQ {
    unsigned int CertSerial; //Revoked cert serial
    time_t RevokeTime;       //Revoked time

    CRLREQ()
    {
        time(&RevokeTime);
    }
} CRLREQ, *LPCRLREQ;

// PEM编码的RSA密钥对信息
typedef struct RSAKEYPAIR {
    int Bits;
    char PublicKey[4096];
    char PrivateKey[4096];

    RSAKEYPAIR()
    {
        memset(this, 0, sizeof(RSAKEYPAIR));
    }
} RSAKEYPAIR, *LPRSAKEYPAIR;

class VerifyCrtChain
{
public:
    VerifyCrtChain();
    ~VerifyCrtChain();

    /* 用证书链初始化(加入指定删除证书) */
    int Init(unsigned int blocktime, const char* cert, int certlen, const std::string delcer = "");

    /* 验证证书 */
    int VerifyCrt(const char* cert, int certlen, bool logerr = true);

    /* 验证证书 */
    int VerifyX509(X509* cert, bool logerr = true);

    /* 将证书加入吊销列表 */
    bool InsertUchain(const char* cert, int certlen);

private:
    X509* m_leaf;

    STACK_OF(X509) * m_uchain;
    X509_STORE* m_store;
};

class CCertificate /*: private Uncopyable */
{
public:
    CCertificate(const char* pCertData, int nCertDataSize, int nFormat);
    CCertificate(const char* pCertPath, int nFormat);
    ~CCertificate();

    bool IsValid() const { return m_isValid; }
    void Print();

    // const X509* GetX509() const { return m_pX509; }
    int GetVersion() const { return m_nVersion; }
    std::string GetSerialNumber() const { return m_strSerialNumber; }
    std::string GetSubjectName() const { return m_strSubjectName; }
    std::string GetIssuerName() const { return m_strIssuerName; }
    CERTSUBJECT GetSubject() const { return m_subject; }
    CERTSUBJECT GetIssuer() const { return m_Issuer; }

    time_t GetNotBefore() const { return m_notBefore; }
    time_t GetNotAfter() const { return m_notAfter; }

    std::string GetCertBase58Str() const;
    std::vector<unsigned char> GetCertContent() const { return m_vecCertContent; }
    std::vector<unsigned char> GetPubkey() const { return m_vecPubkey; }
    // std::vector<unsigned char> GetSignature() const { return m_vecSignature; }

    friend inline bool operator<(const CCertificate& a, const CCertificate& b)
    {
        return a.m_strSerialNumber < b.m_strSerialNumber;
    }

private:
    int Init(const char* pCertFile, int nDataSize, int nFormat = FORMAT_PEM);
    void ParseX509(X509* pX509);

    // X509 *m_pX509;
    int m_nVersion;
    std::string m_strSerialNumber;
    std::string m_strSubjectName;
    std::string m_strIssuerName;
    CERTSUBJECT m_subject;
    CERTSUBJECT m_Issuer;

    time_t m_notBefore;
    time_t m_notAfter;

    std::vector<unsigned char> m_vecCertContent;
    std::vector<unsigned char> m_vecPubkey;
    // std::vector<unsigned char> m_vecSignature;
    bool m_isValid;
};

class CPrivateKey /*: private Uncopyable */
{
public:
    CPrivateKey() : m_strPassword(""), m_isValid(false) {}
    CPrivateKey(const char* pKeyData, int nKeyDataSize, const char* pwd, int nFormat);
    CPrivateKey(const char* pKeyPath, const char* pwd, int nFormat);
    ~CPrivateKey();

    bool IsValid() const { return m_isValid; }
    void Print();

    // const EVP_PKEY* GetKey() const { return m_pKey; }
    std::string GetKeyBase58Str() const;
    std::vector<unsigned char> GetKeyContent() const { return m_vecKeyContent; }
    std::vector<unsigned char> GetPubkey() const { return m_vecPubkey; }
    std::vector<unsigned char> GetPrivkey() const { return m_vecPrivkey; }
    std::string GetPassword() const { return m_strPassword; }

private:
    void ParseKey(EVP_PKEY* pKey);
    int Init(const char* pKeyFile, int nDataSize, const char* pwd, int nFormat = FORMAT_PEM);

    // EVP_PKEY *m_pKey;
    std::vector<unsigned char> m_vecKeyContent;
    std::vector<unsigned char> m_vecPubkey;
    std::vector<unsigned char> m_vecPrivkey;
    std::string m_strPassword;
    bool m_isValid;
};
/**
 * Load certificate X509 object.
 * return not NULL if load is successful.
 * cert cannot be NULL, it should be certificate file path or content pointer.
 */
X509* LoadCert(const char* cert, int certlen, const char* pwd, int format);

/**
 * Load certificate key.
 * return not NULL if load is successful.
 * key cannot be NULL, it should be kay file path or content pointer.
 */
EVP_PKEY* LoadKey(const char* key, int keylen, const char* pwd, int format);

// 判断证书是否在吊销列表中
bool IsInRevoklist(unsigned int itime, std::string& serialno);

// 判断父证书是否为挖矿证书
bool IsIssuerMiner(const char* supcer, int suplen);

// 判断证书上下级关系
bool IsSupsub(const char* supcer, int suplen, const char* subcer, int sublen, unsigned int itime = 0);

// 判断证书上下级关系（X509）
bool IsSupsubX509(X509* supce, X509* subcer, unsigned int itime = 0);

// 判断证书是否为叶子证书
bool IsLeafCert(const char* cert, int certlen, const char* bundle, int bundlen);

// 获取证书的主题信息（全部信息），返回主题的字符串形式
std::string GetCertSubjectString(const char* pubCert, int pubCertLen, int certFormat);

// 获取证书的主题信息
int GetCertSubject(X509* pX509, LPCERTSUBJECT subject);
int GetCertSubject(const char* pubCert, int pubCertLen, int certFormat, LPCERTSUBJECT subject);

// 获取证书的颁发者的主题信息
int GetCertIssuer(X509* pX509, LPCERTSUBJECT issuer);
int GetCertIssuer(const char* pubCert, int pubCertLen, int certFormat, LPCERTSUBJECT subject);

// 获取证书的序列号
std::string GetCertSerialNumber(const char* pubCert, int pubCertLen, int certFormat);
std::string GetCertSerialNumber(const X509* pX509);

// 检查证书有效期,在有效期内返回真，否则返回假
bool CheckCertLife(const char* pubCert, int pubCertLen, int certFormat, time_t ct);

// 通过根证书验证证书
bool CheckCertWithRoot(const char* pubCert, int pubCertLen, int certFormat, const char* rootCert, int rootCertLen, int rootFormat);

// 判断私钥文件是否加密
bool IsEncrypted(const char* priCert, int priCertLen);

// 数字签名
bool CASign(const char* priCert, int priCertLen, int format, const char* pwd, unsigned char* input, long inputLen, unsigned char* output, unsigned int* outputLen);

// 签名验证
bool CAVerify(const char* pubCert, int pubCertLen, int format, const char* input, unsigned int inputLen, unsigned char* sign, unsigned int signLen);

/**
 * get private key from EVP_PKEY object.
 * return 0 is successful.
 * pEvpKey can't be NULL.
 */
int GetPrivKey(EVP_PKEY* pEvpKey, std::vector<unsigned char>& vecPrivKey);

/**
 * get public key from certificate X509 object.
 * return 0 is successful.
 * pCert can't be NULL.
 */
int GetPubKey(EVP_PKEY* pEvpKey, std::vector<unsigned char>& vecPubKey);
int GetCertPubKey(X509* pCert, std::vector<unsigned char>& vecPubkey);

#endif // BITCOIN_CA_H