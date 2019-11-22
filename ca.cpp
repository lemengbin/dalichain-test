#include "ca.h"
#include "pubkey.h"
#include "base58.h"

#include <fstream>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

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
        printf("[ERROR] : bad input format specified for input cert\n");
        goto end;
    }
end:
    if (x509 == NULL) {
        printf("[ERROR] : unable to load certificate\n");
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
            printf("[ERROR] : open CA certificate file error [%s]\n", cert);
            return NULL;
        }
    }
    else {
        if ((in = BIO_new_mem_buf((char *)cert, certlen)) == NULL) {
            printf("[ERROR] : Make Mem Bio Error\n");
            return NULL;
        }
    }

    x509 = load_cert(in, pwd, format);

    if (in != NULL) BIO_free(in);

    return x509;
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

//////////////////////////////////////////////////////////////////
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
        printf("[ERROR] : bad input format specified for key\n");
        goto end;   
    }   
end:   
    if (pkey == NULL)   
        printf("[ERROR] : unable to load Private Key\n");

    return(pkey);   
}

EVP_PKEY* LoadKey(const char *key, int keylen, const char *pwd, int format)   
{   
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL;
    if (keylen == 0) //输入为磁盘文件  
    {   
        if ((in = BIO_new_file(key, "r")) == NULL) {
            printf("[ERROR] : open CA certificate file error [%s]\n", key);
            return NULL;   
        }   
    }   
    else //输入为内存中文件    
    {   
        if ((in = BIO_new_mem_buf((char *)key, keylen)) == NULL) {
            printf("[ERROR] : Make Mem Bio Error\n");  
            return NULL;   
        }   
    }   

    pkey = load_key(in, pwd, format);
    if (in != NULL) BIO_free(in);   

    return pkey;   
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

//////////////////////////////////////////////////////////////////
void CLocalCaManager::InitLocalCaMap()
{
}

CLocalCaManager::CLocalCaManager()
{
    InitLocalCaMap();
}

stCertFile CLocalCaManager::GetCa(const std::string &strSerialNum)
{
    LOCK(m_lock);
    if (m_mapLocalCa.count(strSerialNum))
        return m_mapLocalCa[strSerialNum];
    return stCertFile();
}

stCertFile CLocalCaManager::GetCa(const CKeyID &keyId)
{
    LOCK(m_lock);
    std::map<std::string, stCertFile>::iterator it = m_mapLocalCa.begin();
    while (it != m_mapLocalCa.end())
    {
        stCertFile entry = it->second;
        it++;
        CCertificate cert(entry.strCert.c_str(), FORMAT_PEM);
        CKeyID id = Hash160(cert.GetPubkey());
        if (id == keyId)
            return entry;
    }
    return stCertFile();
}

std::vector<stCertFile> CLocalCaManager::GetLocalCerts()
{
    LOCK(m_lock);
    std::vector<stCertFile> vecCerts;
    if (m_mapLocalCa.empty())
        return vecCerts;

    std::map<std::string, stCertFile>::iterator it = m_mapLocalCa.begin();
    while (it != m_mapLocalCa.end())
    {
        vecCerts.push_back(it->second);
        it++;
    }
    return vecCerts;
}

std::vector<std::string> CLocalCaManager::GetUsbKeyCerts()
{
    LOCK(m_lock);
    std::vector<std::string> certIndexes;
    return certIndexes;
}

CLocalCaManager* GetLocalCaManager()
{
    static CLocalCaManager localCas;
    return &localCas;
}

//////////////////////////////////////////////////////////////////
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
            printf("[ERROR] : No prikey password in config\n");
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
        printf("[ERROR] : EVP_SignInit err\n");
        fRet = false; 
        goto __end;
    } 
    if (!EVP_SignUpdate(&md_ctx, input, inputLen))
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_SignUpdate err\n"); 
        printf("[ERROR] : EVP_SignUpdate err\n");
        fRet = false; 
        goto __end;
    } 
    if (!EVP_SignFinal(&md_ctx, (unsigned char*)output, outputLen, evpKey))
    { 
        //Common::SysLogger.Error(__FILE__, __LINE__, "EVP_SignFinal err \n"); 
        printf("[ERROR] : EVP_SignFinal err\n");
        fRet = false; 
        goto __end;
    } 

    fRet = true;
__end:
    EVP_MD_CTX_cleanup(&md_ctx);

    EVP_PKEY_free(evpKey);
    return fRet;
}

bool IsValidCert(const std::vector<unsigned char> &vecCert, unsigned int nTime)
{
    return false;
}

bool IsValidAddress(const CKeyID &keyId)
{
    if (keyId.IsNull())
        return false;
    std::vector<stCertFile> vecLocalCas = GetLocalCaManager()->GetLocalCerts(); //get pubkeys from local file
    for (stCertFile &certFile : vecLocalCas)
    {
        CCertificate cert(certFile.strCert.c_str(), FORMAT_PEM);
        std::vector<unsigned char> vecPub = cert.GetPubkey();
        uint160 pubId = Hash160(vecPub);
        if (keyId == CKeyID(pubId))
        {
            if (!IsValidCert(cert.GetCertContent(), time(NULL)))
                return false;
            else
                return true;
        }
    }
    return false;
}
