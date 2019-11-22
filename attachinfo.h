#ifndef BITCOIN_ATTACH_INFO_H
#define BITCOIN_ATTACH_INFO_H

#include <string>
#include <vector>
#include <univalue.h>


#define ATTACHVERSION 2    //
#define REVOKECRT_VERSION 1
#define REALNAME_ATTACH_VERSION 1

class CAttachInfo
{
public:
    enum ATTACHType { 
        ATTACH_NULL = 0, 
        ATTACH_CONTRACT, 
        ATTACH_PUBTOKEN, 
        ATTACH_FILEONCHAIN, 
        ATTACH_REVOKECRT, 
        ATTACH_SCANPAY,
        ATTACH_REALNAME,
        };

    CAttachInfo()
    {
        nVersion = ATTACHVERSION;
        vAttachs = NullUniValue;
    }
    ~CAttachInfo(){};

    std::string write(unsigned int prettyIndent = 0, unsigned int indentLevel = 0) const;

    bool read(const char *raw);
    bool read(const std::string& rawStr) {
        return read(rawStr.c_str());
    }

    bool isNull();

    bool addAttach(CAttachInfo::ATTACHType type, const UniValue &obj);

    UniValue getTypeObj(CAttachInfo::ATTACHType inputType);

private:
    int nVersion;
    std::vector<std::string> vTypes;
    //std::vector<UniValue> vAttachs;
    UniValue vAttachs;  //array
};

#endif