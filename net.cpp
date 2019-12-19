#include "net.h"
#include "uint256.h"
#include "hash.h"
#include "version.h"
#include "random.h"
#include "util.h"
#include "netmessagemaker.h"
#include "chainparams.h"

#include <iostream>
#include <list>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

using namespace std;

static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 42 * 1000 * 1000;

static std::atomic<bool> fStopThread(false);
static std::atomic<bool> fRunSendThread(false);
static std::atomic<bool> fRunRecvThread(false);

bool CloseSocket(int& hSocket)
{
    if(hSocket <= 0)
        return false;
#ifdef WIN32
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    hSocket = -1;
    return ret != -1;
}

bool SetSocketNonBlocking(int& hSocket, bool fNonBlocking)
{
    if (fNonBlocking) {
#ifdef WIN32
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == -1) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags | O_NONBLOCK) == -1) {
#endif
            CloseSocket(hSocket);
            return false;
        }
    } else {
#ifdef WIN32
        u_long nZero = 0;
        if (ioctlsocket(hSocket, FIONBIO, &nZero) == -1) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags & ~O_NONBLOCK) == -1) {
#endif
            CloseSocket(hSocket);
            hSocket = -1;
            return false;
        }
    }

    return true;
}

void PushMessage(int& hSocket, CSerializedNetMsg&& msg)
{
    size_t nMessageSize = msg.data.size();
    size_t nTotalSize = nMessageSize + CMessageHeader::HEADER_SIZE;
    //LogPrintf("sending %s (%d bytes)“， msg.command, nMessageSize);

    vector<unsigned char> serializedHeader;
    serializedHeader.reserve(CMessageHeader::HEADER_SIZE);

    uint256 hash = Hash(msg.data.data(), msg.data.data() + nMessageSize);
    CMessageHeader hdr(Params().MessageStart(), msg.command.c_str(), nMessageSize);
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

    CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, serializedHeader, 0, hdr};
    send(hSocket, reinterpret_cast<const char*>(serializedHeader.data()), serializedHeader.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    //LogPrintf("command: %s, header size: %d\n", msg.command.data(), serializedHeader.size());
    if(nMessageSize)
    {
        send(hSocket, reinterpret_cast<const char*>(msg.data.data()), nMessageSize, MSG_NOSIGNAL | MSG_DONTWAIT);
        //LogPrintf("data: %x, data size: %d\n", msg.data.data(), nMessageSize);
    }
}

void PushVersion(int& hSocket)
{
    ServiceFlags nLocalNodeServices = ServiceFlags::NODE_NETWORK;
    static uint64_t id = 0;
    uint64_t nonce = CSipHasher(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())).Write(0xd93e69e2bbfa5735ULL).Write(id++).Finalize();
    int nNodeStartHeight = 0;
    CAddress addrYou = CAddress(CService(), nLocalNodeServices);
    CAddress addrMe = CAddress(CService(), nLocalNodeServices);
    string strSubVersion = "/Satoshi:0.14.1/";
    PushMessage(hSocket, CNetMsgMaker(INIT_PROTO_VERSION).Make("version", PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, time(NULL), addrYou, addrMe, nonce, strSubVersion, nNodeStartHeight, true));
}

bool SendMessage(int& hSocket)
{
    int64_t nVersionTime = 0;
    int64_t nPingTime = 0;

    PushVersion(hSocket);

    while(!fStopThread)
    {
        fRunSendThread = true;
        if(time(NULL) - nVersionTime >= 50)
        {
            PushMessage(hSocket, CNetMsgMaker(INIT_PROTO_VERSION).Make("verack"));
            nVersionTime = time(NULL);
        }

        if(time(NULL) - nPingTime >= 50)
        {
            uint64_t nonce = 0;
            while(nonce == 0)
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            PushMessage(hSocket, CNetMsgMaker(PROTOCOL_VERSION).Make("ping", nonce));
            nPingTime = time(NULL);
        }
        usleep(10000);
    }

    fRunSendThread = false;
    return true;
}

static list<CNetMessage> vRecvMsg;

bool ParseRecvedMessage(const char* pchBuf, unsigned int nBytes)
{
    while(nBytes > 0)
    {
        if(vRecvMsg.empty() || vRecvMsg.back().complete())
            vRecvMsg.push_back(CNetMessage(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION));

        CNetMessage& msg = vRecvMsg.back();

        int handled = 0;
        if(!msg.in_data)
            handled = msg.readHeader(pchBuf, nBytes);
        else
            handled = msg.readData(pchBuf, nBytes);

        if(handled < 0)
            return false;

        if(msg.in_data && msg.hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH)
            return false;

        pchBuf += handled;
        nBytes -= handled;
    }
    return true;
}

bool RecvMessage(int& hSocket)
{
    while(!fStopThread)
    {
        fRunRecvThread = true;
        char pchBuf[0x10000] = {0x00};
        int nBytes = recv(hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
        if(nBytes > 0 && !ParseRecvedMessage(pchBuf, nBytes))
            return false;

        for(auto it = vRecvMsg.begin(); it != vRecvMsg.end();)
        {
            if(!it->complete())
                break;

            string strCommand = it->hdr.GetCommand();
            //LogPrintf("recv command: %s, data size: %d", strCommand, it->hdr.nMessageSize);

            if(strCommand == "ping")
            {
                uint64_t nonce = 0;
                it->vRecv >> nonce;
                //LogPrintf("recv ping data: %llu", nonce);
                PushMessage(hSocket, CNetMsgMaker(PROTOCOL_VERSION).Make("pong", nonce));
            }
            it = vRecvMsg.erase(it);
        }

        usleep(10000);
    }

    fRunRecvThread = false;
    return true;
}

int CNetMessage::readHeader(const char *pch, unsigned int nBytes)
{
    unsigned int nRemaining = 24 - nHdrPos;
    unsigned int nCopy = std::min(nRemaining, nBytes);

    memcpy(&hdrbuf[nHdrPos], pch, nCopy);
    nHdrPos += nCopy;

    if (nHdrPos < 24)
        return nCopy;

    try {
        hdrbuf >> hdr;
    }
    catch (const std::exception&) {
        return -1;
    }

    if (hdr.nMessageSize > MAX_SIZE)
        return -1;

    in_data = true;

    return nCopy;
}

int CNetMessage::readData(const char *pch, unsigned int nBytes)
{
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min(nRemaining, nBytes);

    if (vRecv.size() < nDataPos + nCopy)
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));

    memcpy(&vRecv[nDataPos], pch, nCopy);
    nDataPos += nCopy;

    return nCopy;
}

CNet::CNet()
{
    strIP = "0.0.0.0";
    nPort = 9333;
    hSocket = -1;
    pSendThread = NULL;
    pRecvThread = NULL;
}

CNet::~CNet()
{
    fStopThread = true;

    while(fRunSendThread || fRunRecvThread)
        usleep(10000);

    /*
    if(pSendThread)
    {
        delete pSendThread;
        pSendThread = NULL;
    }

    if(pRecvThread)
    {
        delete pRecvThread;
        pRecvThread = NULL;
    }
    */

    CloseSocket(hSocket);
}

bool CNet::Start(const string& strIPIn, const unsigned short nPortIn)
{
    strIP = strIPIn;
    nPort = nPortIn;

    if(!IsValidIP(strIP))
        return error("Invalid remote node ip: %s", strIP);
    if(nPortIn == 0)
        return error("Invalid remote node port: %d", nPortIn);

    if(!Connect())
        return false;

    pSendThread = new thread(&SendMessage, ref(hSocket));
    pRecvThread = new thread(&RecvMessage, ref(hSocket));

    return true;
}

bool CNet::Connect()
{
    hSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    int set = 1;
#ifdef SO_NOSIGPIPE
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    /*
    if (!SetSocketNonBlocking(hSocket, true))
    {
        CloseSocket(hSocket);
        return error("ConnectSocketDirectly: Setting socket to non-blocking failed, error %d", errno);
    }
    */

    struct sockaddr_in srvAddr;
    srvAddr.sin_family = PF_INET;
    srvAddr.sin_port = htons(nPort);
    srvAddr.sin_addr.s_addr = inet_addr(strIP.c_str());

    if(connect(hSocket, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) == -1)
        return error("Connect to node %s:%d failed %d", strIP, nPort, errno);

    return true;
}
