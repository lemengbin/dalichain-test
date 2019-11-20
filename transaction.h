#ifndef TRANACTION_H
#define TRANACTION_H

#include <vector>
#include <string>

#include "amount.h"
#include "hash.h"
#include "common.h"
#include "uint256.h"
#include "serialize.h"
#include "script/script.h"
#include "compress/include/ZLIBCompress.h"
#include "compress/include/LZ4Compress.h"
#include "compress/include/SnappyCompress.h"

#define BULLOCKCHAIN_BLOCK_COMPRESS_ZIP                            1
#define BULLOCKCHAIN_BLOCK_COMPRESS_LZ4                            2
#define BULLOCKCHAIN_BLOCK_COMPRESS_SNAPPY                         3
#define BULLOCKCHAIN_BLOCK_COMPRESS_METHOD_MASK                    0x07
#define BULLOCKCHAIN_BLOCK_COMPRESS_FLAG                           0x08
#define BULLOCKCHAIN_BLOCK_ENCRYPTION                              0x100

enum BUSINESSTYPE
{
    BUSINESSTYPE_TRANSACTION = 1,
    BUSINESSTYPE_TOKEN,
    BUSINESSTYPE_DATAWRITE,
};

enum BUSINESSTYPE_SUB_EXCHANGE
{
    BUSINESSTYPE_EXCHANGE         = (1 << 8),
    BUSINESSTYPE_EXCHANGE_END     = (1 << 9),
    BUSINESSTYPE_EXCHANGE_SINGLE  = (1 << 10),
};

enum BUSINESSTYPE_SUB_CA
{
    BUSINESSTYPE_REVOKECRT        = (1 << 11),
};


enum BUSINESSTYPE_SUB_CONTRACT
{
    BUSINESSTYPE_CONTRACTCALL         = 1 << 12,
    BUSINESSTYPE_CONTRACTRESULT       = 1 << 13,
    BUSINESSTYPE_CONTRACTRSULT_APPEND = 1 << 14,
};

enum TOKENTYPE
{
    TOKEN_TX,
    TOKEN_CREATE,
    TOKEN_APPEND,
};

enum
{
    TOKEN_NOISSUANCE = 0,
    TOKEN_ISSUANCE=1,
};

enum class EnumTx
{
    TX_NULL = -1,
    TX_GAS = 0,
    TX_TOKEN,
};

class UniValue;

static const int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;

////////////////////////////////////////////////////////////////////////////////
template<typename Stream, typename TxType>
inline void SerializeTokenParam(const TxType& tx, Stream& s)
{
    s << tx.nTokenType;
    s << tx.nAdditional;
    s << tx.nValueLimit;
    s << tx.vTokenIcon;
}

template<typename Stream, typename TxType>
inline void UnserializeTokenParam(TxType& tx, Stream& s)
{
    s >> tx.nTokenType;
    s >> tx.nAdditional;
    s >> tx.nValueLimit;
    s >> tx.vTokenIcon;
}

struct CMutableTokenParam;

class CTokenParam
{
public:
    const uint32_t nTokenType = TOKEN_TX;
    const uint32_t nAdditional = TOKEN_ISSUANCE;
    const CAmount nValueLimit = INT64_MAX;
    const std::vector<uint8_t> vTokenIcon;

    CTokenParam();
    CTokenParam(const CMutableTokenParam& param);
    CTokenParam(CMutableTokenParam& param);
};

struct CMutableTokenParam
{
    uint32_t nTokenType = TOKEN_TX;
    uint32_t nAdditional = TOKEN_ISSUANCE;
    CAmount nValueLimit = INT64_MAX;
    std::vector<uint8_t> vTokenIcon;

    CMutableTokenParam();
    CMutableTokenParam(const CTokenParam& param);

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        SerializeTokenParam(*this, s);
    }

    template <typename Stream>
    inline void Unserialize(Stream& s)
    {
        UnserializeTokenParam(*this, s);
    }

    template <typename Stream>
    CMutableTokenParam(deserialize_type, Stream& s)
    {
        Unserialize(s);
    }
};

////////////////////////////////////////////////////////////////////////////////
class BasicObject
{
public:
    std::vector<std::string> objectID;
    long long utcTime;
    std::string keyInfo;
    std::string latitudeLongitude;
    std::string specification;
    std::string srcHash;
    std::string uRL3rd;

    BasicObject();
    void SetNull();
    bool IsNull() const;
    int ParseJsonString(UniValue& obj , std::string& error_str);
    UniValue ToJsonObject() const;
};

////////////////////////////////////////////////////////////////////////////////
class CBullockChainCompress
{
private:
    CCompressAlgorithmBase *compressObj;
    uint32_t uiFlag;

public:
    CBullockChainCompress(uint32_t uiCompressMethod = 1);
    ~CBullockChainCompress(void);
    void SetNull();
    CCompressAlgorithmBase* GetObject() const;
    uint32_t GetFlag() const;
};

////////////////////////////////////////////////////////////////////////////////
class BullockChainObject
{
public:
    static const int32_t CURRENT_VERSION=0;
    static const int32_t MAX_STANDARD_VERSION=0;

    int32_t nVersion;
    std::string objectID_F;
    int32_t flag;
    long long utcTime;
    std::vector<BasicObject> markList;
    std::string markHash;

    BullockChainObject();
    BullockChainObject(const BullockChainObject& bullockchainObject);
    void SetNull();
    bool IsNull() const;
    std::string ToJsonString() const;
    UniValue ToJsonObject() const;
    char* CompressJsonString(uint32_t uiCompressMethod, uint32_t *pCompDataSize, uint32_t* pTotolSize) const;
    char* DecompressJsonString(uint32_t uiCompressMethod, char* str, uint32_t uiOriginalLength, uint32_t uiCompressedLength);
    BullockChainObject& operator=(const BullockChainObject& other);

    unsigned int GetSerializeSize(int nType=0) const
    {
        if(nType & SER_GETHASH || nType & SER_NETWORK)
        {
            std::string jsonStr = ToJsonString();
            return sizeof(nVersion) + sizeof(uint32_t) + jsonStr.length();
        }

        if(!IsNull())
        {
            uint32_t uiCompDataSize, uiTotolSize;
            uiCompDataSize = uiTotolSize = 0;

            int64_t iCompressMethod = true;
            if(iCompressMethod)
            {
                char *pBuffer = CompressJsonString((uint32_t)iCompressMethod, &uiCompDataSize, &uiTotolSize);
                if(pBuffer)
                {
                    delete [] pBuffer;
                }

                return (sizeof(nVersion) + uiTotolSize + sizeof(uiTotolSize));
            }
            else
            {
                std::string jsonStr = ToJsonString();
                uint32_t jsonstrLen = (uint32_t)jsonStr.length();
                uiTotolSize += jsonstrLen + (sizeof(uint32_t)* 3);
                return (sizeof(nVersion) + uiTotolSize + sizeof(uiTotolSize));
            }
        }
        else
        {
            return (sizeof(nVersion) + sizeof(uint32_t));
        }
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write((char*)&nVersion, sizeof(nVersion));

        if(s.GetType() & SER_GETHASH || s.GetType() & SER_NETWORK)
        {
            std::string jsonStr = ToJsonString();
            uint32_t jsonstrLen = (uint32_t)jsonStr.length();
            s.write((char*)&jsonstrLen, sizeof(jsonstrLen));
            if(jsonstrLen > 0)
            {
                s.write((char*)jsonStr.c_str(), jsonstrLen);
            }
            return;

        }

        uint32_t uiCompDataSize, uiTotolSize;
        uiCompDataSize = uiTotolSize = 0;

        if(!IsNull())
        {
            int64_t iCompressMethod = true;
            if(iCompressMethod)
            {
                char *pBuffer = CompressJsonString((uint32_t)iCompressMethod, &uiCompDataSize, &uiTotolSize);
                if(NULL == pBuffer)
                    return;
                s.write(pBuffer, uiTotolSize + sizeof(uiTotolSize));
                delete [] pBuffer;
            }
            else
            {
                uint32_t uiPad = 0;
                std::string jsonStr = ToJsonString();
                uint32_t jsonstrLen = (uint32_t)jsonStr.length();
                uiTotolSize += jsonstrLen + (sizeof(uint32_t)* 3);
                s.write((char*)&uiTotolSize, sizeof(uiTotolSize));

                for(int i = 0; i < 3; i++)
                {
                    s.write((char*)&uiPad, sizeof(uiPad));
                }

                s.write((char*)jsonStr.c_str(), jsonstrLen);
            }
        }
        else
        {
            s.write((char*)&uiTotolSize, sizeof(uiTotolSize));
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read((char*)&nVersion, sizeof(nVersion));

        if(s.GetType() & SER_GETHASH  || s.GetType() & SER_NETWORK)
        {
            uint32_t json_str_len = 0;
            s.read((char*)&json_str_len, sizeof(json_str_len));
            if(json_str_len > 0)
            {
                char *str = new char [json_str_len + 1];
                memset(str, 0, json_str_len + 1);
                s.read(str, json_str_len);

                //std::string error_str;
                //ParseJsonString(str, error_str);
                delete [] str;
                str = NULL;
            }
            return;
        }

        uint32_t uiContentFlags, uiTotolSize, uiOriginalLength, uiCompressedLength;
        uiContentFlags = uiTotolSize = uiOriginalLength = uiCompressedLength = 0;

        s.read((char*)&uiTotolSize, sizeof(uiTotolSize));

        if(uiTotolSize > 0)
        {
            char *str = new char [uiTotolSize + 1];
            memset(str, 0, uiTotolSize + 1);
            s.read(str, uiTotolSize);

            uint32_t offset = 0;
            memcpy(&uiContentFlags, str + offset, sizeof(uiContentFlags));
            offset += sizeof(uiContentFlags);
            memcpy(&uiOriginalLength, str + offset, sizeof(uiOriginalLength));
            offset += sizeof(uiOriginalLength);
            memcpy(&uiCompressedLength, str + offset, sizeof(uiCompressedLength));
            offset += sizeof(uiCompressedLength);

            int64_t iCompressMethod = true;

            int64_t iCompressMethodRead = uiContentFlags & BULLOCKCHAIN_BLOCK_COMPRESS_METHOD_MASK;
            if(iCompressMethodRead != iCompressMethod)
            {
                delete [] str;
                return;
            }

            if(uiContentFlags & BULLOCKCHAIN_BLOCK_COMPRESS_FLAG)
            {
                char *ori = NULL;

                ori = DecompressJsonString(uiContentFlags & BULLOCKCHAIN_BLOCK_COMPRESS_METHOD_MASK, str + offset, uiOriginalLength, uiCompressedLength);
                if(ori)
                {
                    //std::string error_str;
                    //ParseJsonString(ori, error_str);
                    delete [] ori;
                    ori = NULL;
                }
            }
            else if(uiTotolSize > (sizeof(uint32_t)* 3))
            {
                //std::string error_str;
                //ParseJsonString(str + offset, error_str);
            }
            delete [] str;
        }
    }
};

////////////////////////////////////////////////////////////////////////////////
class COutPoint
{
public:
    uint256 hash;
    int32_t nType;
    uint32_t n;

    COutPoint();
    COutPoint(uint256 hashIn, EnumTx nTypeIn, uint32_t nIn);
    void SetNull();
    bool IsNull() const;
    bool IsTokenType() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(nType);
        READWRITE(n);
    }
};

////////////////////////////////////////////////////////////////////////////////
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness;

    static const uint32_t SEQUENCE_FINAL = 0xffffffff;
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    CTxIn();
    CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }
};

////////////////////////////////////////////////////////////////////////////////
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut();
    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);
    void SetNull();
    bool IsNull() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
    }
};

////////////////////////////////////////////////////////////////////////////////
template<typename Stream, typename TxType>
inline void SerializeGasToken(const TxType& tx, Stream& s)
{
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s << tx.strPayCurrencySymbol;

    unsigned char flags = 0;
    if(fAllowWitness)
    {
        if(tx.HasWitness())
            flags |= 1;
    }

    if(flags)
    {
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }

    s << tx.vin;
    s << tx.vout;

    if(flags & 1)
    {
        for(size_t i = 0; i < tx.vin.size(); i++)
            s << tx.vin[i].scriptWitness.stack;
    }
}

template<typename Stream, typename TxType>
inline void UnserializeGasToken(TxType& tx, Stream& s)
{
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s >> tx.strPayCurrencySymbol;

    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();

    s >> tx.vin;
    if(tx.vin.size() == 0 && fAllowWitness)
    {
        s >> flags;
        if(flags != 0)
        {
            s >> tx.vin;
            s >> tx.vout;
        }
    }
    else
    {
        s >> tx.vout;
    }

    if((flags & 1) && fAllowWitness)
    {
        flags ^= 1;
        for(size_t i = 0; i < tx.vin.size(); i++)
            s >> tx.vin[i].scriptWitness.stack;
    }

    if(flags)
        throw std::ios_base::failure("Unknown transaction optional data");
}

struct CMutableGasToken;

class CGasToken
{
public:
    const std::string strPayCurrencySymbol;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;

    CGasToken();
    CGasToken(const CMutableGasToken& gas);
    CGasToken(CMutableGasToken& gas);

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        SerializeGasToken(*this, s);
    }

    template <typename Stream>
    CGasToken(deserialize_type, Stream& s) : CGasToken(CMutableGasToken(deserialize, s)) {}

    bool HasWitness() const;
    bool Empty() const;
};

struct CMutableGasToken
{
    std::string strPayCurrencySymbol;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;

    CMutableGasToken();
    CMutableGasToken(const CGasToken& gas);

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        SerializeGasToken(*this, s);
    }

    template <typename Stream>
    inline void Unserialize(Stream& s)
    {
        UnserializeGasToken(*this, s);
    }

    template <typename Stream>
    CMutableGasToken(deserialize_type, Stream& s)
    {
        Unserialize(s);
    }

    bool HasWitness() const;
    void clear();
    bool Empty() const;
};

////////////////////////////////////////////////////////////////////////////////
class CTransaction;
struct CMutableTransaction;

typedef std::shared_ptr<const CTransaction> CTransactionRef;
static inline CTransactionRef MakeTransactionRef() { return std::make_shared<const CTransaction>(); }
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

typedef std::shared_ptr<CMutableTransaction> CMutableTransactionRef;
static inline CMutableTransactionRef MakeMutableTransactionRef() { return std::make_shared<CMutableTransaction>(); }
template <typename Tx> static inline CMutableTransactionRef MakeMutableTransactionRef(Tx&& txIn) { return std::make_shared<CMutableTransaction>(std::forward<Tx>(txIn)); }

template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType& tx, Stream& s)
{
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s << tx.nVersion;
    s << tx.nBusinessType;
    if(BUSINESSTYPE_TOKEN == tx.GetBusinessType())
        SerializeTokenParam(tx.tokenParam, s);
    else if(BUSINESSTYPE_DATAWRITE == tx.GetBusinessType())
        s << tx.bullockchainObject;


    s << tx.strPayCurrencySymbol;

    unsigned char flags = 0;
    if(fAllowWitness)
    {
        if(tx.HasWitness())
            flags |= 1;
    }
    if(flags)
    {
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }

    s << tx.vin;
    s << tx.vout;

    if(flags & 1)
    {
        for(size_t i = 0; i < tx.vin.size(); i++)
            s << tx.vin[i].scriptWitness.stack;
    }

    s << tx.nLockTime;
    SerializeGasToken(tx.gasToken, s);

    if(tx.nVersion > 2)
        s << tx.strAttach;

    if(tx.nVersion > 5 && tx.IsExchangeType())
    {
        if(!tx.IsExchangeEndFlag() &&!tx.IsExchangeSingle() && tx.txExch != NULL)
            s << *(tx.txExch);

        if(!(s.GetType() & SER_GETHASH))
        {
            if(tx.IsExchangeSingle() || tx.IsExchangeEndFlag())
                s << tx.theOtherHash;
        }
    }
}

template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType& tx, Stream& s)
{
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s >> tx.nVersion;
    s >> tx.nBusinessType;

    if(BUSINESSTYPE_TOKEN == tx.GetBusinessType())
        UnserializeTokenParam(tx.tokenParam, s);
    else if(BUSINESSTYPE_DATAWRITE == tx.GetBusinessType())
        s >> tx.bullockchainObject;

    s >> tx.strPayCurrencySymbol;

    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();

    s >> tx.vin;
    if(tx.vin.size() == 0 && fAllowWitness)
    {
        s >> flags;
        if(flags != 0)
        {
            s >> tx.vin;
            s >> tx.vout;
        }
    }
    else
    {
        s >> tx.vout;
    }

    if((flags & 1) && fAllowWitness)
    {
        flags ^= 1;
        for(size_t i = 0; i < tx.vin.size(); i++)
            s >> tx.vin[i].scriptWitness.stack;
    }

    if(flags)
        throw std::ios_base::failure("Unknown transaction optional data");

    s >> tx.nLockTime;
    UnserializeGasToken(tx.gasToken, s);

    if(tx.nVersion > 2)
        s >> tx.strAttach;

    if(tx.nVersion > 5 && tx.IsExchangeType())
    {
        if(!tx.IsExchangeEndFlag() && !tx.IsExchangeSingle())
        {
            tx.txExch = MakeMutableTransactionRef();
            s >> *(tx.txExch);
        }

        if(tx.IsExchangeSingle() || tx.IsExchangeEndFlag())
            s >> tx.theOtherHash;
    }
}

class CTransaction
{
public:
    static const int32_t CURRENT_VERSION = 6;
    static const int32_t MAX_STANDARD_VERSION = 6;

    const int32_t nVersion;
    const int32_t nBusinessType = BUSINESSTYPE_TRANSACTION;
    const CTokenParam tokenParam;
    const BullockChainObject bullockchainObject;
    const std::string strPayCurrencySymbol;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;
    const CGasToken gasToken;
    // the min version is 3
    const std::string strAttach;
    // the min version is 6
    const CTransactionRef txExch = NULL;
    const uint256 theOtherHash;

private:
    uint256 hash;
    uint256 ComputeHash() const;

public:
    CTransaction();
    CTransaction(const CMutableTransaction& tx);
    CTransaction(CMutableTransaction&& tx);
    bool IsNull() const;
    uint256 GetHash() const;
    uint256 GetWitnessHash() const;
    bool HasWitness() const;
    bool IsTokenFlag() const;
    int32_t IsExchangeType() const;
    int32_t IsExchangeEndFlag() const;
    int32_t IsExchangeSingle() const;
    int32_t IsRevokecrlType() const;
    int32_t GetBusinessType() const;
    int32_t GetSubType() const;

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        SerializeTransaction(*this, s);
    }
};

struct CMutableTransaction
{
    int32_t nVersion;
    int32_t nBusinessType = BUSINESSTYPE_TRANSACTION;
    CMutableTokenParam tokenParam;
    BullockChainObject bullockchainObject;
    std::string strPayCurrencySymbol;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    CMutableGasToken gasToken;
    std::string strAttach;
    CMutableTransactionRef txExch = NULL;
    uint256 theOtherHash;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        SerializeTransaction(*this, s);
    }

    template <typename Stream>
    inline void Unserialize(Stream& s)
    {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s)
    {
        Unserialize(s);
    }

    friend bool operator==(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return a.GetHash() == b.GetHash();
    }

    uint256 GetHash() const;
    bool HasWitness() const;
    int32_t GetBusinessType() const;
    void SetBusinessType(int32_t nBusinessTypeIn);
    void SetExchangeType(int32_t nExchangeType);
    int32_t IsExchangeType() const;
    int32_t IsExchangeEndFlag() const;
    int32_t IsExchangeSingle() const;
    int32_t GetSubType() const;
};

#endif
