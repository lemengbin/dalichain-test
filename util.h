#ifndef UTIL_H
#define UTIL_H

#include "tinyformat.h"

#include <atomic>
#include <stdio.h>
#include <string>
#include <sstream>
#include <boost/filesystem/path.hpp>

int LogPrintStr(const std::string &str);

#define LogPrint LogPrintf

#define LogPrintf(...) do { \
    LogPrintStr(tfm::format(__VA_ARGS__)); \
} while(0)

template<typename... Args>
bool error(const char* fmt, const Args&... args)
{
    LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}

template<typename T>
std::string Convert2Str(T &val)
{
    std::ostringstream s;
    s << val;
    return s.str();
}

template<typename T>
bool ConvertStr2(std::string & str, T & val)
{
    std::istringstream stream;
    stream.str(str);
    if(stream >> val)
        return true;
    return false;
}

void FileCommit(FILE *file);
bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest);
void ToLowerCase(std::string& str);

#endif
