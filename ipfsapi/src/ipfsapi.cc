#include <ipfs/client.h>
#include <ipfs/ipfsapi.h>
#include <nlohmann/json.hpp>
#include <sstream>

bool IpfsPin(const std::string & strObjectId, const std::string & strIP, unsigned short nPort)
{
    try {
      ipfs::Client client(strIP, nPort);
            
      /** [ipfs::Client::PinAdd] */
      /* std::string object_id = "QmdfTbBqBPQ7VNxZEYEj14V...1zR1n" for example. */
      client.PinAdd(strObjectId);
    
      /* An example output:
      Pinned object: QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n
      */
      /** [ipfs::Client::PinAdd] */
    
      /** [ipfs::Client::PinLs__a] */
      ipfs::Json pinned;
    
      client.PinLs(&pinned);
      /* An example output:
      List of all pinned objects:
      {
        "Keys": {
          "QmNYaS23te5Rja36U94JoSTuMxJZmBEnHN8KEcjR6rGRGn": {
            "Type": "indirect"
          },
          "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn": {
            "Type": "recursive"
          },
          "Qmf5t6BgYbiT2usHRToVzLu5DNHfH39S4dq6JTxf69Npzt": {
            "Type": "indirect"
          }
        }
      }
      */
      /** [ipfs::Client::PinLs__a] */
    
      /** [ipfs::Client::PinLs__b] */
      /* std::string object_id = "QmdfTbBqBPQ7VNxZEYEj14V...1zR1n" for example. */
      client.PinLs(strObjectId, &pinned);
    
      /* An example output:
      List pinned objects under QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n:
      {
        "Keys": {
          "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n": {
            "Type": "recursive"
          }
        }
      }
      */
      /** [ipfs::Client::PinLs__b] */
    
      /** [ipfs::Client::PinRm] */
      /* std::string object_id = "QmdfTbBqBPQ7VNxZEYEj14V...1zR1n" for example. */
    
      bool unpinned;
      try {
        client.PinRm(strObjectId, ipfs::Client::PinRmOptions::NON_RECURSIVE);
        unpinned = true;
      } catch (const std::exception&) {
        unpinned = false;
      }
    
      if (unpinned) {
        throw std::runtime_error(
            "Unpinning " + strObjectId +
            " non-recursively succeeded but should have failed.");
      }
    
      client.PinRm(strObjectId, ipfs::Client::PinRmOptions::RECURSIVE);
      /** [ipfs::Client::PinRm] */
    } catch (const std::exception& ) {
//      std::cerr << e.what() << std::endl;
      return false;
    }

    return true;
}

inline uint160 uint160S(const std::string& str)
{
    uint160 rv;
    rv.SetHex(str);
    return rv;
}

void ParseJson(const std::string& input, ipfs::Json* result) {
  try {
    *result = ipfs::Json::parse(input);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string(e.what()) + "\nInput JSON:\n" + input);
  }
}

bool IpfsPutString(const std::string & strName, const std::string & str4Upload,std::string & ipfshash, const bool fFielUpload, const std::string & strIP, unsigned short nPort)
{
    try {
    ipfs::Client client(strIP, nPort);

    /** [ipfs::Client::FilesAdd] */
    ipfs::Json add_result;
    client.FilesAdd(
        {{strName, fFielUpload ? ipfs::http::FileUpload::Type::kFileName : ipfs::http::FileUpload::Type::kFileContents, str4Upload}},
        &add_result);
    /* An example output:
    [
      {
        "path": "foo.txt",
        "hash": "QmWPyMW2u7J2Zyzut7TcBMT8pG6F2cB4hmZk1vBJFBt1nP",
        "size": 4
      }
      {
        "path": "bar.txt",
        "hash": "QmVjQsMgtRsRKpNM8amTCDRuUPriY8tGswsTpo137jPWwL",
        "size": 1176
      },
    ]
    */
    /** [ipfs::Client::FilesAdd] */
        ipfshash = add_result[0]["hash"];
    
  } catch (const std::exception& ) {
    //std::cout << e.what() << std::endl;
    return false;
  }

  return true;
}

bool IpfsGet(const std::string &strQuery, std::string & strRet, const std::string & strIP, unsigned short nPort)
{
    try {
        ipfs::Client client(strIP, nPort);
        /** [ipfs::Client::FilesGet] */
        std::stringstream contents;
        client.FilesGet(
            strQuery,
            &contents);

        strRet = contents.str();
   }catch (const std::exception& ) {
//       std::cerr << e.what() << std::endl;
       return false;
  }

  return true;
}

bool IpfsGetp(const std::string &strQuery, std::string & strRet, ipfs::Client * client)
{
    try {
        //ipfs::Client client(strIP, nPort);
        /** [ipfs::Client::FilesGet] */
        std::stringstream contents;
        client->FilesGet(
            strQuery,
            &contents);

        strRet = contents.str();
   }catch (const std::exception&) {
       //std::cerr << e.what() << std::endl;
       return false;
  }

  return true;
}

bool IpfsGets(std::vector<std::pair<std::string, std::string>> &vecQuery, const std::string & strIP, unsigned short nPort)
{
   
  ipfs::Client client(strIP, nPort);
  /** [ipfs::Client::FilesGet] */
  //std::vector<std::string>::iterator it;
  for(auto it = vecQuery.begin(); it != vecQuery.end(); it++)
  {
    it->second = "";
    std::stringstream contents;

    try 
    {
      client.FilesGet(it->first, &contents);
    }
    catch (const std::exception&) 
    {
       //std::cerr << e.what() << std::endl;
       
       continue;
    }

    it->second = contents.str();
  }
  
  return true;
}
