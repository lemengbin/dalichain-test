#ifndef NETMESSAGEMAKER_H
#define NETMESSAGEMAKER_H

#include "net.h"
#include "serialize.h"
#include <sys/timeb.h>

class CNetMsgMaker
{
public:
    CNetMsgMaker(int nVersionIn) : nVersion(nVersionIn){}

    template <typename... Args>
    CSerializedNetMsg Make(int nFlags, std::string sCommand, Args&&... args) const
    {
        CSerializedNetMsg msg;
        msg.command = std::move(sCommand);
        if(!strcmp(msg.command.data(), "headers"))
            CVectorWriter{ SER_NETWORK|SER_GETHEADER, nFlags | nVersion, msg.data, 0, std::forward<Args>(args)... };
        else
            CVectorWriter{ SER_NETWORK, nFlags | nVersion, msg.data, 0, std::forward<Args>(args)... };
        return msg;
    }

    template <typename... Args>
    CSerializedNetMsg Make(std::string sCommand, Args&&... args) const
    {
        return Make(0, std::move(sCommand), std::forward<Args>(args)...);
    }

private:
    const int nVersion;
};

#endif
