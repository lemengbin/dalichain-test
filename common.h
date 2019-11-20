#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <sstream>

#ifdef WIN32
typedef signed char           int8_t;
typedef signed short          int16_t;
typedef signed int            int32_t;
typedef signed long long      int64_t;
typedef unsigned char         uint8_t;
typedef unsigned short        uint16_t;
typedef unsigned int          uint32_t;
typedef unsigned long long    uint64_t;
#endif

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

#endif
