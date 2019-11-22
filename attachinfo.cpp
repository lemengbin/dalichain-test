#include "attachinfo.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>

std::string toStrType(CAttachInfo::ATTACHType type)
{
    std::string strType = "";
    switch(type)
    {
        case CAttachInfo::ATTACH_NULL:
            break;
        case CAttachInfo::ATTACH_CONTRACT:
            strType = "contract";
            break;
        case CAttachInfo::ATTACH_PUBTOKEN:
            strType = "pubtoken";
            break;
        case CAttachInfo::ATTACH_FILEONCHAIN:
            strType = "fileonchain";
            break;
        case CAttachInfo::ATTACH_REVOKECRT:
            strType = "revokecrt";
            break;
        case CAttachInfo::ATTACH_SCANPAY:
            strType = "scanpay";
            break;
        case CAttachInfo::ATTACH_REALNAME:
            strType = "realname";
            break;
    }
    return strType;
}

bool CAttachInfo::read(const char *raw)
{
    if(!raw || strlen(raw) == 0)
        return true;

    UniValue obj_main(UniValue::VOBJ);
    if (!obj_main.read(raw))
        return false;

    //int m_version = 0;
    std::string m_strtype = "";
    
    UniValue u_tmp1 = find_value(obj_main, "attachVersion");
    /* BEGIN----------------向前兼容-----------------*/
    if (u_tmp1.isNull())
    {
        if (obj_main.exists("sigCertificates"))
        {
		    nVersion = 1;
            addAttach(CAttachInfo::ATTACH_REALNAME, obj_main);
            return true;
        }
        else if (obj_main.exists("RevokeCertificate"))
        {
            nVersion = 1;
            addAttach(CAttachInfo::ATTACH_REVOKECRT, obj_main);
            return true;
        }
        else
            return false;
    }
    /* END------------------------------------------*/

    if (u_tmp1.isNum())
        nVersion = u_tmp1.get_int();
    else
        return false;

    UniValue u_tmp2 = find_value(obj_main, "attachType");
    if (u_tmp2.isStr())
    {
        m_strtype = u_tmp2.get_str();
        boost::split(vTypes, m_strtype, boost::is_any_of("-"));
    }
    else
        return false;

    //std::vector<UnspentInfo> vecunspt;
    UniValue u_tmp3 = find_value(obj_main, "attachList");
    if (u_tmp3.isArray())
    {
        vAttachs = u_tmp3.get_array();
        if(vAttachs.size() != vTypes.size())
            return false;
    }
    else
        return false;

    return true;
}

bool CAttachInfo::isNull()
{
    return vTypes.empty();
}

UniValue CAttachInfo::getTypeObj(CAttachInfo::ATTACHType inputType)
{
    std::string strType = toStrType(inputType);
    for (unsigned int n = 0; n < vTypes.size(); n++)
    {
        if(vTypes[n] == strType)
            return vAttachs[n];
    }

    return NullUniValue;
}

std::string CAttachInfo::write(unsigned int prettyIndent, unsigned int indentLevel) const
{
    if (vTypes.size() == 0)
        return "";
    
    std::string strType = "";
    for (unsigned int n = 0; n< vTypes.size(); n++)
    {
        strType += vTypes[n];
        if(n != (vTypes.size() - 1))
            strType += "-";
    }

    UniValue attach(UniValue::VOBJ);
    attach.push_back(Pair("attachVersion", nVersion));
    attach.push_back(Pair("attachType",  strType));
    attach.push_back(Pair("attachList",  vAttachs));

    return attach.write(prettyIndent, indentLevel);
}

bool CAttachInfo::addAttach(CAttachInfo::ATTACHType type, const UniValue &obj)
{
    UniValue vAttachsTemp(UniValue::VARR);

    std::string sType = toStrType(type);
    if(sType == "")
        return false;

    if(vTypes.size() != vAttachs.size())
        return false;

    bool isAdded = false;
    for (unsigned int n = 0; n< vTypes.size(); n++)
    {
        if (vTypes[n] == sType)
        {
            vAttachsTemp.push_back(obj);
            isAdded = true;
        }
        else
            vAttachsTemp.push_back(vAttachs[n]);
    }
    if (!isAdded)
    {
        vTypes.push_back(sType);
        vAttachsTemp.push_back(obj);
    }
    vAttachs = vAttachsTemp;

    return true;
}