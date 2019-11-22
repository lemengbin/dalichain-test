#ifndef CA_H
#define CA_H

#include <string>
#include <vector>
#include <map>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "sync.h"

#define FORMAT_DER 1
#define FORMAT_PEM 3
#define FORMAT_NET 4
#define FORMAT_P12 5

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

class CCertificate
{
public:
    CCertificate(const char* pCertData, int nCertDataSize, int nFormat);
    CCertificate(const char* pCertPath, int nFormat);
    ~CCertificate();

    bool IsValid() const { return m_isValid; }
    void Print();

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

    friend inline bool operator<(const CCertificate& a, const CCertificate& b)
    {
        return a.m_strSerialNumber < b.m_strSerialNumber;
    }

private:
    int Init(const char* pCertFile, int nDataSize, int nFormat = FORMAT_PEM);
    void ParseX509(X509* pX509);

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
    bool m_isValid;
};

//////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////
struct stCertFile
{
    std::string strBundle;
    std::string strCert;
    std::string strKey;
    std::string strPwd; 

    bool Empty() {return strCert.empty() || strKey.empty();}
};

class CKeyID;
class CLocalCaManager
{
public:
    CLocalCaManager();
    ~CLocalCaManager(){}

    stCertFile GetCa(const std::string &strSerialNum);
    stCertFile GetCa(const CKeyID &keyId);
    std::vector<stCertFile> GetLocalCerts();
    std::vector<std::string> GetUsbKeyCerts();

private:
    void InitLocalCaMap();

private:
    std::map<std::string, stCertFile> m_mapLocalCa; //map of serial number and ca info
    CCriticalSection m_lock;
};

CLocalCaManager* GetLocalCaManager();

//////////////////////////////////////////////////////////////////
bool CASign(const char* priCert, int priCertLen, int format, const char* pwd, unsigned char* input, long inputLen, unsigned char* output, unsigned int* outputLen);
bool IsValidAddress(const CKeyID &keyId);

#endif
