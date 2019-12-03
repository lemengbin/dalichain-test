#include "camempool.h"

#include <boost/filesystem.hpp>
#include <fstream>
#include "util.h"
#include "chainparams.h"
//#include "clientversion.h"
#include "hash.h"
#include "random.h"
#include "tinyformat.h"
#include "streams.h"
#include "base58.h"
#include "ca.h"

#include "ipfsapi/include/ipfs/ipfsapi.h"
#include "version.h"

static std::string s_bundleContent = "";

void LoadPersonalCaBundle()
{
    std::string personalBundlePath = ""; //GetArg("-personalcertbundle", "");
    
    if(personalBundlePath != "")
    {
        std::ifstream in(personalBundlePath.data());
        if(in) {
            std::ostringstream  tmp;
            tmp << in.rdbuf();
            s_bundleContent = tmp.str();
        }
    }
    if (s_bundleContent.empty())
        LogPrintf("Error: can not get bundle content from personalcertbundle path %s\n", personalBundlePath.c_str());
}

bool IsFromLocalPersonalBundle(const std::vector<unsigned char> &vecCert)
{
    if (s_bundleContent.empty())
        LoadPersonalCaBundle();
    if (s_bundleContent.empty())
    {
        LogPrintf("Error: can not load personal bundle\n");
        return false;
    }
    VerifyCrtChain crtChain;
    crtChain.Init(0, s_bundleContent.c_str(), s_bundleContent.size());
    if (crtChain.VerifyCrt((char*)vecCert.data(), vecCert.size()) != 1)
        return false;
    return true;
}

bool IsPersonalCaOverdue(const std::vector<unsigned char> &vecCert, unsigned int nTime)
{
    if (!CheckCertLife((char*)vecCert.data(), vecCert.size(), FORMAT_PEM, nTime))
        return true;
    return false;
}

bool IsPersonalCaRevoked(const std::vector<unsigned char> &vecCert, unsigned int nTime)
{
    std::string strSerialNum = GetCertSerialNumber((char*)vecCert.data(), vecCert.size(), FORMAT_PEM);
    if (IsInRevoklist(nTime, strSerialNum))
        return true;
    return false;
}

bool IsValidCert(const std::vector<unsigned char> &vecCert, unsigned int nTime)
{
    if (vecCert.empty())
        return false;
    if (!IsFromLocalPersonalBundle(vecCert))
        return false; //ca not from out bundle, invalid!!!
    if (IsPersonalCaOverdue(vecCert, nTime))
        return false; //ca overdue, invalid!
    if (IsPersonalCaRevoked(vecCert, nTime))
        return false; //ca revoked, invalid!
    return true;
}

std::string GetPrivkeyContent(const std::string &filePath)
{
    std::string strContent;
    if (filePath.empty())
        return strContent;
    std::ifstream in(filePath.data());
    if(in) {
        std::ostringstream  tmp;
        tmp << in.rdbuf();
        strContent = tmp.str();
    }
    return strContent;
}

void GetFilePaths(const std::string &strPath, std::vector<std::string> &vecFilePaths)
{
    boost::filesystem::path filePath(strPath);
    if (!boost::filesystem::exists(filePath))
    {
        LogPrintf("%s:%d File path %s not existed\n", __FUNCTION__, __LINE__, strPath.c_str());
        return;
    }
    boost::filesystem::directory_iterator end_iter;
    for (boost::filesystem::directory_iterator it(filePath); it != end_iter; it++)
    {
        if (boost::filesystem::is_directory(it->status()))
            vecFilePaths.push_back(it->path().string());
    }
}

void GetFileNames(const std::string &strPath, std::vector<std::string> &vecFileNames)
{
    boost::filesystem::path filePath(strPath);
    if (!boost::filesystem::exists(filePath))
    {
        LogPrintf("%s:%d File path %s not existed\n", __FUNCTION__, __LINE__, strPath.c_str());
        return;
    }
    boost::filesystem::directory_iterator end_iter;
    for (boost::filesystem::directory_iterator it(filePath); it != end_iter; it++)
    {
        if (boost::filesystem::is_regular_file(it->status()))
            vecFileNames.push_back(it->path().string());
    }
}

bool GetLocalCertificates(std::vector<stCertFile> &vecCertGroups)
{
    std::string certPath = ""; // GetArg("-personalcerts", "");
    std::vector<std::string> vecChildCertPaths;
    GetFilePaths(certPath, vecChildCertPaths);
    if (vecChildCertPaths.empty())
        return false;
    for (size_t i = 0; i < vecChildCertPaths.size(); i++)
    {
        std::vector<std::string> vecChildFiles;
        GetFileNames(vecChildCertPaths[i], vecChildFiles);
        if (vecChildFiles.empty())
            continue;
        stCertFile certInfo;
        for (size_t a = 0; a < vecChildFiles.size(); a++)
        {
            std::string fileName = vecChildFiles[a];
            if (fileName.find("bundle") != std::string::npos)
                certInfo.strBundle = fileName;
            else if (fileName.find(".crt") != std::string::npos)
                certInfo.strCert = fileName;
            else if (fileName.find(".key") != std::string::npos)
                certInfo.strKey = fileName;
            else if (fileName.find(".pwd") != std::string::npos)
            {
                std::ifstream in(fileName.data());
                if(in) {
                    std::ostringstream  tmp;
                    tmp << in.rdbuf();
                    certInfo.strPwd = tmp.str();
                }
            }
        }
        if (certInfo.Empty())
            continue;
        vecCertGroups.push_back(certInfo);
    }
    if (vecCertGroups.empty())
        return false;

    return true;
}

void CLocalCaManager::InitLocalCaMap()
{
    if (s_bundleContent.empty())
        LoadPersonalCaBundle();
    
    std::vector<stCertFile> vecCertGroups;
    if (!GetLocalCertificates(vecCertGroups))
    {
        LogPrintf("%s:%d can not find local certificates\n", __FUNCTION__, __LINE__);
        return;
    }
    for (size_t i = 0; i < vecCertGroups.size(); i++)
    {
        stCertFile certInfo = vecCertGroups[i];
        CCertificate cert(certInfo.strCert.c_str(), FORMAT_PEM);
        if (!IsValidCert(cert.GetCertContent()))
        {
            LogPrintf("%s:%d Cert from %s is invalid\n", __FUNCTION__, __LINE__, certInfo.strCert.c_str());
            continue;
        }
        std::string serialNum = cert.GetSerialNumber();
        m_mapLocalCa[serialNum] = certInfo;
    }
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

bool CLocalCaManager::IsLocalCertValid(const std::string &strSerialNum)
{
    LOCK(m_lock);
    stCertFile localFile = GetCa(strSerialNum);
    if (localFile.Empty())
        return false;
    CCertificate cert(localFile.strCert.c_str(), FORMAT_PEM);
    if (!cert.IsValid())
        return false;
    if (!IsValidCert(cert.GetCertContent(), time(NULL)))
        return false;
    return true;
}

bool CLocalCaManager::IsLocalPrivkeyValid(const CKeyID &keyId, const std::string &strPwd)
{
    LOCK(m_lock);
    if (keyId.IsNull())
        return false;
    
    std::map<std::string, stCertFile>::iterator it = m_mapLocalCa.begin();
    while (it != m_mapLocalCa.end())
    {
        stCertFile entry = it->second;
        it++;
        CCertificate cert(entry.strCert.c_str(), FORMAT_PEM);
        CKeyID id = Hash160(cert.GetPubkey());
        if (id == keyId)
        {
            CPrivateKey pk(entry.strKey.c_str(), strPwd.empty() ? "" : strPwd.c_str(), FORMAT_PEM);
            if (pk.IsValid())
                return true;
            else
                return false;
        }
    }
    return false;
}

CLocalCaManager* GetLocalCaManager()
{
    static CLocalCaManager localCas;
    return &localCas;
}

CCaMempool::CCaMempool()
{
    m_maxSize = 10000; // GetArg("-maxcertifates", 10000);
    m_cutRate = 1000; // GetArg("-certificatecutrate", 1000);
    if (m_cutRate > m_maxSize)
        m_cutRate = m_maxSize;
    m_initSize = 0;
    std::vector<std::string> ipaddresses;
    std::vector<std::string> ports;
    /*
    if (mapMultiArgs.count("-ipfsipaddress"))
    {
        ipaddresses = mapMultiArgs.at("-ipfsipaddress");
    }
    if (mapMultiArgs.count("-ipfsport"))
    {
        ports = mapMultiArgs.at("-ipfsport");
    }
    */
    if (ipaddresses.empty() || ports.empty())
    {
        m_ipPorts["127.0.0.1"] = 5001;
    }
    else if (ipaddresses.size() != ports.size())
    {
        LogPrintf("Error: ipfs ip address and ports must map one by one!\n");
        return;
    }
    else
    {
        for (size_t i = 0; i < ipaddresses.size(); i++)
        {
            m_ipPorts[ipaddresses[i]] = std::stoi(ports[i]);
        }
    }

    Unstore();
    init();
}

CCaMempool::CCaMempool(unsigned long size, unsigned long cutRate)
{
    m_maxSize = size;
    m_cutRate = cutRate;
    if (m_cutRate > m_maxSize)
        m_cutRate = m_maxSize;
    m_initSize = 0;
    std::vector<std::string> ipaddresses;
    std::vector<std::string> ports;
    /*
    if (mapMultiArgs.count("-ipfsipaddress"))
    {
        ipaddresses = mapMultiArgs.at("-ipfsipaddress");
    }
    if (mapMultiArgs.count("-ipfsport"))
    {
        ports = mapMultiArgs.at("-ipfsport");
    }
    */
    if (ipaddresses.empty() || ports.empty())
    {
        m_ipPorts["127.0.0.1"] = 5001;
    }
    else if (ipaddresses.size() != ports.size())
    {
        LogPrintf("Error: ipfs ip address and ports must map one by one!\n");
        return;
    }
    else
    {
        for (size_t i = 0; i < ipaddresses.size(); i++)
        {
            m_ipPorts[ipaddresses[i]] = std::stoi(ports[i]);
        }
    }

    Unstore();
    init();
}

CCaMempool::CCaMempool(const std::string &ipfsIp, unsigned short ipfsPort)
{
    m_maxSize = 10000; // GetArg("-maxcertifates", 10000);
    m_cutRate = 100; // GetArg("-certificatecutrate", 1000);
    if (m_cutRate > m_maxSize)
        m_cutRate = m_maxSize;
    m_initSize = 0;
    std::vector<std::string> ipaddresses;
    std::vector<std::string> ports;
    /*
    if (mapMultiArgs.count("-ipfsipaddress"))
    {
        ipaddresses = mapMultiArgs.at("-ipfsipaddress");
    }
    if (mapMultiArgs.count("-ipfsport"))
    {
        ports = mapMultiArgs.at("-ipfsport");
    }
    */
    if (ipaddresses.empty() || ports.empty())
    {
        m_ipPorts["127.0.0.1"] = 5001;
    }
    else if (ipaddresses.size() != ports.size())
    {
        LogPrintf("Error: ipfs ip address and ports must map one by one!\n");
        return;
    }
    else
    {
        for (size_t i = 0; i < ipaddresses.size(); i++)
        {
            m_ipPorts[ipaddresses[i]] = std::stoi(ports[i]);
        }
    }
    m_ipPorts[ipfsIp] = ipfsPort;

    Unstore();
    init();
}

CCaMempool::CCaMempool(unsigned long size, unsigned long cutRate, const std::string &ipfsIp, unsigned short ipfsPort)
{
    m_maxSize = size;
    m_cutRate = cutRate;
    if (m_cutRate > m_maxSize)
        m_cutRate = m_maxSize;
    m_initSize = 0;
    std::vector<std::string> ipaddresses;
    std::vector<std::string> ports;
    /*
    if (mapMultiArgs.count("-ipfsipaddress"))
    {
        ipaddresses = mapMultiArgs.at("-ipfsipaddress");
    }
    if (mapMultiArgs.count("-ipfsport"))
    {
        ports = mapMultiArgs.at("-ipfsport");
    }
    */
    if (ipaddresses.empty() || ports.empty())
    {
        m_ipPorts["127.0.0.1"] = 5001;
    }
    else if (ipaddresses.size() != ports.size())
    {
        LogPrintf("Error: ipfs ip address and ports must map one by one!\n");
        return;
    }
    else
    {
        for (size_t i = 0; i < ipaddresses.size(); i++)
        {
            m_ipPorts[ipaddresses[i]] = std::stoi(ports[i]);
        }
    }
    m_ipPorts[ipfsIp] = ipfsPort;

    Unstore();
    init();
}


CCaMempool::~CCaMempool()
{
    Flush();
    m_certificates.clear();
}

void CCaMempool::SetLimitAndCutNum(unsigned long size, unsigned long num)
{
    m_maxSize = size;
    if (num > size)
        m_cutRate = m_maxSize;
    else
        m_cutRate = num;
}

bool CCaMempool::IsExistedBySerialNum(const std::string &serialNum)
{
    if (serialNum.empty())
        return false;
    serialIndexed::iterator it = certOrderBySerialNum.find(serialNum);
    if (it == certOrderBySerialNum.end())
        return false;
    return true;
}

bool CCaMempool::IsExistedByPubkey(const std::vector<unsigned char> &pubkey)
{
    if (pubkey.empty())
        return false;
    pubkeyIndexed::iterator it = certOrderByPubkey.find(pubkey);
    if (it == certOrderByPubkey.end())
        return false;
    return true;
}

bool CCaMempool::IsExistedByCertificate(const std::vector<unsigned char> &certificate)
{
    if (certificate.empty())
        return false;
    dataIndexed::iterator it = certOrderByData.find(certificate);
    if (it == certOrderByData.end())
        return false;
    return true;
}

bool CCaMempool::IsExistedByIpfsKey(const std::string &ipfsKey)
{
    if (ipfsKey.empty())
        return false;
    ipfsIndexed::iterator it = certOrderByIpfsKey.find(ipfsKey);
    if (it == certOrderByIpfsKey.end())
        return false;
    return true;
}

std::vector<unsigned char> CCaMempool::GetCertFromIPFS(const std::string &ipfsKey)
{
    /*
    if (IsArgSet("-ipfsclient"))
    {
        std::vector<unsigned char> vecCert;
        std::string strRet;
        if (!IpfsGet(ipfsKey, strRet))
            return vecCert;
        vecCert.insert(vecCert.end(), (unsigned char*)strRet.data(), (unsigned char*)strRet.data() + strRet.size());
        return vecCert;
    }
    else
    */
        return std::vector<unsigned char>();
}

bool CCaMempool::Store(const std::vector<unsigned char> &cert, const std::string &serialNum, const std::string &ipfskey, const std::vector<unsigned char> &pubkey, bool valid)
{
    if (cert.empty() || serialNum.empty() || ipfskey.empty() || pubkey.empty())
        return false;
    if (IsExistedBySerialNum(serialNum))
        return false;
    CaEntry newEntry;
    newEntry.data = cert;
    newEntry.serialNum = serialNum;
    newEntry.pubkey = pubkey;
    newEntry.time = time(NULL);
    newEntry.ipfsKey = ipfskey;
    newEntry.bValid = valid;
    if (m_certificates.size() >= m_maxSize)
    {
        if (!CutSome())
            return false;
    }
    m_certificates.insert(newEntry);
    return true;
}

bool CCaMempool::Unstore()
{
    // open input file, and associate with CAutoFile
    boost::filesystem::path pathAddr = /*GetDataDir() / */ "certificates.dat";
    FILE *file = fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: Failed to open file %s", __func__, pathAddr.string());

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathAddr);
    uint64_t dataSize = 0;
    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();
    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
    if (hashIn != hashTmp)
        return error("%s: Checksum mismatch, data corrupted", __func__);

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (network specific magic number) and ..
        ssPeers >> FLATDATA(pchMsgTmp);
        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
            return error("%s: Invalid network magic number", __func__);

        // de-serialize 
        ssPeers >> m_initSize;
        for (int i = 0; i < m_initSize; i++)
        {
            CaEntry oneCa;
            ssPeers >> oneCa;
            m_certificates.insert(oneCa);
        }
    }
    catch (const std::exception& e) {
        // de-serialization failed, print error
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    return true;
}

void CCaMempool::Clear()
{
    m_certificates.clear();
}

bool CCaMempool::IsValidCertificate(const std::vector<unsigned char> &strCert, unsigned int nTime)
{
    return IsValidCert(strCert, nTime);
}

bool CCaMempool::IsValidAddress(const CKeyID &keyId)
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

bool CCaMempool::RemoveCertBySerialNum(const std::string &serialNum)
{
    if (certOrderBySerialNum.empty())
        return false;
    serialIndexed::iterator it = certOrderBySerialNum.find(serialNum);
    if (it == certOrderBySerialNum.end())
    {
        return false;
    }
    certOrderBySerialNum.erase(it);
    return true;
}

bool CCaMempool::RemoveCertByIpfsKey(const std::string &ipfsKey)
{
    if (certOrderByIpfsKey.empty())
        return false;
    ipfsIndexed::iterator it = certOrderByIpfsKey.find(ipfsKey);
    if (it == certOrderByIpfsKey.end())
    {
        return false;  
    }
    certOrderByIpfsKey.erase(it);
    return true;
}

std::vector<unsigned char> CCaMempool::GetCertBySerialNum(const std::string &serialNum)
{
    std::vector<unsigned char> vecCert;
    if (serialNum.empty())
        return vecCert;    
    serialIndexed::iterator it = certOrderBySerialNum.find(serialNum);
    if (it != certOrderBySerialNum.end())
    {
        vecCert = it->data;
        time_t now = time(NULL);
        // we backup here in case modify failed and container will delete the pointed item, so we need re-add it into container
        CaEntry temp = *it;
        temp.time = now;
        if (!IsValidCertificate(vecCert, now))
            temp.bValid = false;
        if (!certOrderBySerialNum.modify(it, Ca_Time(now)) || !certOrderBySerialNum.modify(it, Ca_BValid(temp.bValid)))
        {
            m_certificates.insert(temp);
        }
    }
    return vecCert;
}

std::vector<unsigned char> CCaMempool::GetCertByIpfsKey(const std::string &ipfsKey)
{
    std::vector<unsigned char> vecCert;
    if (ipfsKey.empty())
        return vecCert;
    ipfsIndexed::iterator it = certOrderByIpfsKey.find(ipfsKey);
    if (it != certOrderByIpfsKey.end())
    {
        vecCert = it->data;
        time_t now = time(NULL);
        // we backup here in case modify failed and container will delete the item it pointed, so we need re-add into container
        CaEntry temp = *it;
        temp.time = now;
        if (!IsValidCertificate(vecCert, now))
            temp.bValid = false;
        if (!certOrderByIpfsKey.modify(it, Ca_Time(now)) || (!temp.bValid && !certOrderByIpfsKey.modify(it, Ca_BValid(temp.bValid))))
        {
            m_certificates.insert(temp);
        }
    }
    else
    {
        vecCert = GetCertFromIPFS(ipfsKey);
    }
}

std::vector<unsigned char> CCaMempool::GetCertByKeyId(const CKeyID &keyId)
{
    std::vector<unsigned char> vecRet;
    if (keyId.IsNull())
        return vecRet;
    pubkeyIndexed::iterator it = certOrderByPubkey.begin(); //get pubkeys from local file
    while (it != certOrderByPubkey.end())
    {
        uint160 pubId = Hash160(it->pubkey);
        if (keyId == CKeyID(pubId))
            return it->data;
        it++;
    }
    return vecRet;
}

std::vector<unsigned char> CCaMempool::GetCert(int type, const std::string &key)
{
    std::vector<unsigned char> vecCert;
    if (key.empty())
        return vecCert;
    if (type == CA_FROM_IPFS)// from ipfs
    {
        vecCert = GetCertByIpfsKey(key);
    }
    else if (type == CA_FROM_LOCAL_SERAIL) // by ca serial number
    {
        vecCert = GetCertBySerialNum(key);
    }
    return vecCert;
}

bool CCaMempool::GetRealNameKeyId(const std::string &serialNum, CKeyID &keyId)
{
    if (serialNum.empty())
        return false;
    serialIndexed::iterator it = certOrderBySerialNum.find(serialNum);
    if (it == certOrderBySerialNum.end())
        return false;
    std::vector<unsigned char> vecPubkey = it->pubkey;
    if (vecPubkey.empty())
        return false;
    keyId = Hash160(vecPubkey);
    return true;
}

bool CCaMempool::IsMine(const CKeyID &keyId)
{
    if (keyId.IsNull())
        return false;
    std::vector<stCertFile> vecLocalCas = GetLocalCaManager()->GetLocalCerts(); //get pubkeys from local file
    for (stCertFile &certFile : vecLocalCas)
    {
        CCertificate cert(certFile.strCert.c_str(), FORMAT_PEM);
        // is mine even though certificate is invalid in many situations
        /*if (!IsValidCert(cert.GetCertContent(), time(NULL)))
            continue;*/
        std::vector<unsigned char> vecPub = cert.GetPubkey();
        uint160 pubId = Hash160(vecPub);
        if (keyId == CKeyID(pubId))
            return true;
    }
    return false;
}

bool CCaMempool::Flush()
{
    size_t nSize = certOrderBySerialNum.size();
    if (nSize == 0)
    {
        return false;
    }
    CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
    ssPeers << FLATDATA(Params().MessageStart());
    ssPeers << nSize;
    serialIndexed::iterator it = certOrderBySerialNum.begin();
    while (it != certOrderBySerialNum.end())
    {
        ssPeers << *it;
        it++;
    }
    uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string strFile = strprintf("certificates.dat.%04x", randv);
    boost::filesystem::path pathTmp = /*GetDataDir() / */ strFile;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try {
        fileout << ssPeers;
    }
    catch (const std::exception& e) {
        return error("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing certificates.dat, if any, with new certificates.dat.XXXX
    boost::filesystem::path pathAddr = /*GetDataDir() / */ "certificates.dat";
    if (!RenameOver(pathTmp, pathAddr))
        return error("%s: Rename-into-place failed", __func__);
}

void CCaMempool::init()
{
    if (s_bundleContent.empty())
        LoadPersonalCaBundle();
    
    std::vector<stCertFile> vecCertGroups;
    if (!GetLocalCertificates(vecCertGroups))
    {
        LogPrintf("%s:%d can not find local certificates\n", __FUNCTION__, __LINE__);
        return;
    }
    for (size_t i = 0; i < vecCertGroups.size(); i++)
    {
        stCertFile certFile = vecCertGroups[i];
        CCertificate cert(certFile.strCert.c_str(), FORMAT_PEM);
        if (!IsValidCert(cert.GetCertContent()))
        {
            LogPrintf("%s:%d: Cert from %s is invalid\n", __FUNCTION__, __LINE__, certFile.strCert.c_str());
            continue;
        }
        if (certOrderBySerialNum.find(cert.GetSerialNumber()) != certOrderBySerialNum.end())
        {
            LogPrintf("%s:%d: Cert existed, Path is %s, serial number is %s\n", __FUNCTION__, __LINE__, certFile.strCert.c_str(), cert.GetSerialNumber().c_str());
            continue;
        }
        CaEntry entry;
        entry.bValid = true;
        entry.data = cert.GetCertContent();
        entry.ipfsKey = strprintf("Local%d", m_certificates.size());
        entry.pubkey = cert.GetPubkey();
        entry.serialNum = cert.GetSerialNumber();
        entry.time = time(NULL);
        m_certificates.insert(entry);
    }
}

bool CCaMempool::CutSome()
{
    size_t totalSize = certOrderByTime.size();
    if (totalSize == 0)
        return false;
    int pos = totalSize - totalSize * m_cutRate / m_maxSize;
    if (pos < 0)
        return false;
    int index = 0;
    timeIndexed::iterator it = certOrderByTime.begin();
    while (it != certOrderByTime.end())
    {
        if (index >= pos)
            certOrderByTime.erase(it);
        index++;
        it++;
    }
    return true;
}

CCaMempool* GetCaMempool()
{
    static CCaMempool caMem;
    return &caMem;
}

