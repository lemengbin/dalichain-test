#ifndef DALI_IPFSAPI_H
#define DALI_IPFSAPI_H

#include "uint256.h"
namespace ipfs {
    class Client;
}

bool IpfsPin(const std::string & strObjectId, const std::string & strIP = "127.0.0.1", unsigned short nPort = 5001);
bool IpfsPutString(const std::string & strName, const std::string & str4Upload, std::string & ipfshash, const bool fFielUpload = false, const std::string & strIP = "127.0.0.1", unsigned short nPort = 5001);
bool IpfsGet(const std::string &strQuery, std::string & strRet, const std::string & strIP = "127.0.0.1", unsigned short nPort = 5001);
bool IpfsGetp(const std::string &strQuery, std::string & strRet, ipfs::Client * client);
bool IpfsGets(std::vector<std::pair<std::string, std::string>> &vecQuery, const std::string & strIP = "127.0.0.1", unsigned short nPort = 5001);

#endif
