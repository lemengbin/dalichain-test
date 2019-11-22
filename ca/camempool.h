#ifndef _CAMEMPOOL_H
#define _CAMEMPOOL_H

// #include "GlobalProfile.h"

#include <string>
#include <vector>
#include <map>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>

#include "serialize.h"
#include "pubkey.h"
#include <time.h>
// #include "ca.h"
#include "sync.h"

class CCertificate;
class CPrivateKey;

// to check personal ca if they are from the same bundle, overdue and revoked?
bool IsFromLocalPersonalBundle(const std::vector<unsigned char> &vecCert);
bool IsPersonalCaOverdue(const std::vector<unsigned char> &vecCert, unsigned int nTime);
bool IsPersonalCaRevoked(const std::vector<unsigned char> &vecCert, unsigned int nTime);

//验证证书是否过期、是否吊销、上级证书是否合法
bool IsValidCert(const std::vector<unsigned char> &vecCert, unsigned int nTime = time(NULL));

std::string GetPrivkeyContent(const std::string filePath);

struct stCertFile
{
    std::string strBundle; //cert bundle file path
    std::string strCert; //cert file path
    std::string strKey; //cert key file path
    std::string strPwd; 

    bool Empty() {return strCert.empty() || strKey.empty();}
};

class CLocalCaManager
{
public:
    CLocalCaManager();
    ~CLocalCaManager(){}

    stCertFile GetCa(const std::string &strSerialNum);
    stCertFile GetCa(const CKeyID &keyId);
    std::vector<stCertFile> GetLocalCerts();
    std::vector<std::string> GetUsbKeyCerts();
    bool IsLocalCertValid(const std::string &strSerialNum);

    bool IsLocalPrivkeyValid(const CKeyID &keyId, const std::string &strPwd = "");

private:
    void InitLocalCaMap();

private:
    std::map<std::string, stCertFile> m_mapLocalCa; //map of serial number and ca info
    CCriticalSection m_lock;
};

CLocalCaManager* GetLocalCaManager();

enum enCaFromType
{
    CA_FROM_IPFS = 1,       //from ipfs
    CA_FROM_LOCAL_SERAIL,   //from serial number
    CA_FROM_LOCAL_PUBKEY,   //from pubkey
    CA_FROM_WEB,            //from website

    CA_FROM_OTHER           //unknown origin
};

struct CaSignType
{
    int type; //1-local privkey, 2-usb key
    std::string keyFile;
    std::string pwd;
};

struct CaAttachType
{
    int type; //1-ipfs-key, 2-ca info
    int protoType;//default 1, 1-x509
    std::string data;
};
    
/*ca entry*/
struct CaEntry
{
    std::vector<unsigned char> data; // ca data
    std::vector<unsigned char> pubkey; // ca pubkey
    std::string serialNum; //ca serial number
    std::string ipfsKey; // key on ipfs to get ca
    uint64_t time = 0; //accept time
    bool bValid = true; //to check if it is valid or revoked

    template<typename Stream>
    void Serialize(Stream &s) const
    {
        s << data.size();
        for (size_t i = 0; i < data.size(); i++)
            s << data[i];
        s << pubkey.size();
        for (size_t i = 0; i < pubkey.size(); i++)
            s << pubkey[i];
        s << serialNum;
        s << ipfsKey;
        s << time;
        s << bValid;
    }
    
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        size_t nSize = 0;
        s >> nSize;
        for (size_t i = 0; i < nSize; i++)
        {
            unsigned char ch;
            s >> ch;
            data.push_back(ch);
        }
        nSize = 0;
        s >> nSize;
        for (size_t i = 0; i < nSize; i++)
        {
            unsigned char ch;
            s >> ch;
            pubkey.push_back(ch);
        }
        s >> serialNum;
        s >> ipfsKey;
        s >> time;
        s >> bValid;
    }

    CaEntry() = default;
};

class Ca_Time
{
public:
    Ca_Time(unsigned long ulTime):m_time(ulTime){}

    void operator()(CaEntry &entry)
    {
        entry.time = m_time;
    }

private:
    unsigned long m_time;
};

class Ca_BValid
{
public:
    Ca_BValid(bool isValid):m_isValid(isValid){}

    void operator()(CaEntry &entry)
    {
        entry.bValid = m_isValid;
    }

private:
    bool m_isValid;
};

/*ca database for get ca or store ca*/
class CCaMempool
{
public:
    CCaMempool();
    CCaMempool(unsigned long size, unsigned long cutRate);
    CCaMempool(const std::string &ipfsIp, unsigned short ipfsPort);
    CCaMempool(unsigned long size, unsigned long cutRate, const std::string &ipfsIp, unsigned short ipfsPort);
    ~CCaMempool();

    // set max size of database and number of reduce of the total certificates
    void SetLimitAndCutNum(unsigned long size, unsigned long num);
    // set ipfs address and port for database to get certificates
    void SetIpfsIpPort(const std::string &ipfsIp, unsigned short ipfsPort) { m_ipPorts[ipfsIp] = ipfsPort; }

    // check if it is in database
    bool IsExistedBySerialNum(const std::string &serialNum);
    bool IsExistedByPubkey(const std::vector<unsigned char> &pubkey);
    bool IsExistedByCertificate(const std::vector<unsigned char> &certificate);
    bool IsExistedByIpfsKey(const std::string &ipfsKey);

    std::vector<unsigned char> GetCertFromIPFS(const std::string &ipfsKey);
    //store certificate, if the new storing makes the database size over limitation, it will cut some entries and then store the new one
    bool Store(const std::vector<unsigned char> &cert, const std::string &serialNum, const std::string &ipfskey, const std::vector<unsigned char> &pubkey, bool valid = true);

    size_t Size() { return m_certificates.size(); }
    //get certificates
    bool Unstore();
    //clear certificates and serial number
    void Clear();

    bool IsValidCertificate(const std::vector<unsigned char> &strCert, unsigned int nTime);
    bool IsValidAddress(const CKeyID &keyId);
    
    //remove certificate by serial number for some reasons, such as timeout, expire or revoked.
    bool RemoveCertBySerialNum(const std::string &serialNum);
    bool RemoveCertByIpfsKey(const std::string &ipfsKey);
    //get certificate from IPFS key
    
    std::vector<unsigned char> GetCertBySerialNum(const std::string &serialNum);
    std::vector<unsigned char> GetCertByIpfsKey(const std::string &ipfsKey);
    std::vector<unsigned char> GetCertByKeyId(const CKeyID &keyId);
    //get certificate by serial number, if the serial number is not found in the database, it will search it from IPFS, and update this one
    //into database, otherwise it will update the time of the existed
    std::vector<unsigned char> GetCert(int type, const std::string &key);

    bool GetRealNameKeyId(const std::string &serialNum, CKeyID &keyId);
    bool IsMine(const CKeyID &keyId);

    bool Flush(); //flush into certificates.dat

private:
    void init();
    bool CutSome(); //cut some entries of certificates by time
private:
    unsigned long m_maxSize; //the max size of db
    unsigned long m_cutRate; //the ratio which the oldest certificates would be cut off from db, so that new certificates could be stored
    std::map<std::string, unsigned short> m_ipPorts; // ipfs ip and port map
    size_t m_initSize;

    typedef boost::multi_index_container<
        CaEntry,
        boost::multi_index::indexed_by<
            boost::multi_index::ordered_unique<boost::multi_index::member<CaEntry, std::string, &CaEntry::serialNum> >,
            boost::multi_index::ordered_unique<boost::multi_index::member<CaEntry, std::vector<unsigned char>, &CaEntry::data> >,
            boost::multi_index::ordered_unique<boost::multi_index::member<CaEntry, std::string, &CaEntry::ipfsKey> >,
            boost::multi_index::ordered_non_unique<boost::multi_index::member<CaEntry, std::vector<unsigned char>, &CaEntry::pubkey> >,
            boost::multi_index::ordered_non_unique<boost::multi_index::member<CaEntry, uint64_t, &CaEntry::time> >
        >
    > indexed_ca_map;

    typedef indexed_ca_map::nth_index<0>::type serialIndexed;
    typedef indexed_ca_map::nth_index<1>::type dataIndexed;
    typedef indexed_ca_map::nth_index<2>::type ipfsIndexed;
    typedef indexed_ca_map::nth_index<3>::type pubkeyIndexed;
    typedef indexed_ca_map::nth_index<4>::type timeIndexed;
    
    indexed_ca_map m_certificates; //multi indexed container of serial number and certificates

    serialIndexed& certOrderBySerialNum = boost::multi_index::get<0>(m_certificates);
    dataIndexed& certOrderByData = boost::multi_index::get<1>(m_certificates);
    ipfsIndexed& certOrderByIpfsKey = boost::multi_index::get<2>(m_certificates);
    pubkeyIndexed& certOrderByPubkey = boost::multi_index::get<3>(m_certificates);
    timeIndexed& certOrderByTime = boost::multi_index::get<4>(m_certificates);
};

CCaMempool* GetCaMempool(); //all ca memory pool

#endif
