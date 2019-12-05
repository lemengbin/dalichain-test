#ifndef NET_H
#define NET_H

#include <string>
#include <vector>
#include <string.h>
#include <arpa/inet.h>
#include <thread>

#include "serialize.h"
#include "version.h"
#include "protocol.h"
#include "streams.h"

enum ServiceFlags : uint64_t {
    NODE_NONE = 0,
    NODE_NETWORK = (1 << 0),
    NODE_GETUTXO = (1 << 1),
    NODE_BLOOM = (1 << 2),
    NODE_WITNESS = (1 << 3),
    NODE_XTHIN = (1 << 4),
};

class CNetAddr
{
public:
    unsigned char ip[16];
    uint32_t scopeId;

    CNetAddr()
    {
        memset(ip, 0, sizeof(ip));
        scopeId = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(FLATDATA(ip));
    }
};

class CService : public CNetAddr
{
public:
    unsigned short port;

    CService()
    {
        port = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(FLATDATA(ip));
        unsigned short portN = htons(port);
        READWRITE(FLATDATA(portN));
        if (ser_action.ForRead())
            port = ntohs(portN);
    }
};

class CAddress : public CService
{
public:
    CAddress()
    {
        Init();
    }

    CAddress(CService ipIn, ServiceFlags nServicesIn) : CService(ipIn)
    {
        Init();
        nServices = nServicesIn;
    }

    void Init()
    {
        nServices = NODE_NONE;
        nTime = 100000000;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        if (ser_action.ForRead())
        Init();
        int nVersion = s.GetVersion();
        if (s.GetType() & SER_DISK)
            READWRITE(nVersion);
        if ((s.GetType() & SER_DISK) ||
            (nVersion >= CADDR_TIME_VERSION && !(s.GetType() & SER_GETHASH)))
            READWRITE(nTime);
        uint64_t nServicesInt = nServices;
        READWRITE(nServicesInt);
        nServices = (ServiceFlags)nServicesInt;
        READWRITE(*(CService*)this);
    }

    // TODO: make private (improves encapsulation)
public:
    ServiceFlags nServices;

    // disk and network only
    unsigned int nTime;
};

class CNet
{
public:
    std::string strIP;
    unsigned short nPort;

    int hSocket;
    std::thread* pSendThread;
    std::thread* pRecvThread;

    CNet();
    ~CNet();

    bool Start(const std::string& strIPIn = "192.168.0.61", const unsigned short nPortIn = 9444);
    bool Connect();
};

struct CSerializedNetMsg
{
    CSerializedNetMsg() = default;
    CSerializedNetMsg(CSerializedNetMsg&&) = default;
    CSerializedNetMsg& operator=(CSerializedNetMsg&&) = default;
    CSerializedNetMsg(const CSerializedNetMsg& msg) = delete;
    CSerializedNetMsg& operator=(const CSerializedNetMsg&) = delete;

    std::vector<unsigned char> data;
    std::string command;
};

class CNetMessage {
public:
    bool in_data;                   // parsing header (false) or data (true)

    CDataStream hdrbuf;             // partially received header
    CMessageHeader hdr;             // complete header
    unsigned int nHdrPos;

    CDataStream vRecv;              // received message data
    unsigned int nDataPos;

    int64_t nTime;                  // time (in microseconds) of message receipt.

    CNetMessage(const CMessageHeader::MessageStartChars& pchMessageStartIn, int nTypeIn, int nVersionIn) : hdrbuf(nTypeIn, nVersionIn), hdr(pchMessageStartIn), vRecv(nTypeIn, nVersionIn) {
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        nTime = 0;
    }

    bool complete() const
    {
        if (!in_data)
            return false;
        return (hdr.nMessageSize == nDataPos);
    }

    int readHeader(const char *pch, unsigned int nBytes);
    int readData(const char *pch, unsigned int nBytes);
};

void PushMessage(int& hSocket, CSerializedNetMsg&& msg);

#endif
