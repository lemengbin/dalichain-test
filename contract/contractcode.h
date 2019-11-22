#ifndef CONTRACT_CODE_H
#define CONTRACT_CODE_H

#include <vector>

#include "serialize.h"
#include "base58.h"
#include "utilstrencodings.h"

//typedef prevector<100, unsigned char> PrevectorContractCode;

namespace VM {
class CContractCode
{
public:
    static const int32_t CURRENT_VERSION = 1;
    int nVersion = CURRENT_VERSION;
    std::string strCodeType = "javascript";
    std::vector<unsigned char> vcode;  

    CContractCode() = default;
    CContractCode(std::vector<unsigned char> _vcode) : vcode(_vcode){}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(strCodeType);
        READWRITE(vcode);
    }

    std::string ToString() const;
};

// void InitContractCodeDB(void);
// void FlushContractCodeDB(void);

// bool ContractIsExist(const CContractAddress& address);
// bool AddNewContract(const CContractAddress& address, CContractCode& code);
// bool ContractGetCode(const CContractAddress& address, CContractCode& code);


// static const char DB_CONTRACTCODE = 'c';

// extern CContractViewDB<DB_CONTRACTCODE, CContractAddress, CContractCode, CDBWrapper, CDBIterator, CDBBatch> * ptrContractCodeDB;

static std::string EncodeContractCode(std::vector<unsigned char> vecCode)
{
    return HexStr(vecCode);
}

static std::vector<unsigned char> DecodeContractCode(std::string strCode)
{
    return ParseHex(strCode);
}

}

#endif

