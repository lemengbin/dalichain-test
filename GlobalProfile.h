#ifndef GLOBAL_PROFILE_H
#define GLOBAL_PROFILE_H

#include <string>

class GlobalProfile
{
public:
    static const std::string  strPayCurrencySymbol;
    static const std::string  strGasPayCurrencySymbol;
};

extern std::string g_strPasswd;
extern std::string g_strPrikeyCrt;
extern std::string g_strBundleCrt;

#endif
