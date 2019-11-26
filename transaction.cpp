#include "transaction.h"
#include "univalue.h"
#include "GlobalProfile.h"

#define PARSE_JSON_SUCCESS       0
#define PARSE_JSON_OBJECT_FAIL   1
#define PARSE_JSON_ARRAY_FAIL    2
#define PARSE_JSON_STR_FAIL      3
#define READ_JSON_STR_FAIL       4

#define JSON_OBJECT_JUDGMENT(str, obj, error_str) \
if(!obj.isObject()) \
{\
    error_str.append("Object judgment :parse error:").append(str); \
    return PARSE_JSON_OBJECT_FAIL;\
}

#define JSON_STR_JUDGMENT(objJson, modeval, val, name, error_str) \
modeval = find_value(objJson, name); \
if(modeval.isStr()) \
    val = modeval.get_str(); \
else \
{ \
    error_str.append("Object parse json std::string error : ").append(name); \
    return PARSE_JSON_STR_FAIL;\
}

#define JSON_STR_JUDGMENT2(objJson, modeval, val, name, error_str) \
modeval = find_value(objJson, name); \
if(modeval.isStr()) \
    val = modeval.get_str();

////////////////////////////////////////////////////////////////////////////////
CTokenParam::CTokenParam() : nTokenType(TOKEN_TX), nAdditional(TOKEN_ISSUANCE), nValueLimit(INT64_MAX) {}
CTokenParam::CTokenParam(const CMutableTokenParam& param) : nTokenType(param.nTokenType), nAdditional(param.nAdditional), nValueLimit(param.nValueLimit), vTokenIcon(param.vTokenIcon) {}
CTokenParam::CTokenParam(CMutableTokenParam& param) : nTokenType(param.nTokenType), nAdditional(param.nAdditional), nValueLimit(param.nValueLimit), vTokenIcon(std::move(param.vTokenIcon)) {}

CMutableTokenParam::CMutableTokenParam(): nTokenType(TOKEN_TX), nAdditional(TOKEN_ISSUANCE), nValueLimit(INT64_MAX) {}
CMutableTokenParam::CMutableTokenParam(const CTokenParam& param) : nTokenType(param.nTokenType), nAdditional(param.nAdditional), nValueLimit(param.nValueLimit), vTokenIcon(param.vTokenIcon) {}

////////////////////////////////////////////////////////////////////////////////
BasicObject::BasicObject()
{
    SetNull();
}

void BasicObject::SetNull()
{
    objectID.clear();
    utcTime = 0;
    keyInfo.clear();
    latitudeLongitude.clear();
    srcHash.clear();
    uRL3rd.clear();
}

bool BasicObject::IsNull() const
{
    return objectID.empty() && 0 == keyInfo.size();
}

int BasicObject::ParseJsonString(UniValue& obj , std::string& error_str)
{
    std::string val;
    UniValue modeval;

    JSON_OBJECT_JUDGMENT(obj.write(), obj, error_str)
    UniValue v = find_value(obj, "objectID");
    if(v.isArray())
    {
        objectID.clear();
        UniValue inputs = v.get_array();

        for(unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++)
        {
            const UniValue& input = inputs[inpIdx];
            if(input.isStr())
                objectID.push_back(input.get_str());
            else
            {
                error_str.append("Object parse json array error : ").append("BullockChainObject objectID");
                return PARSE_JSON_STR_FAIL;
            }
        }
    }

    JSON_STR_JUDGMENT2(obj, modeval, val, "utcTime", error_str)
    if(!modeval.isNull() && !ConvertStr2(val, utcTime)) {
        error_str.append("BasicObject parse json utcTime error : ").append("not number");
        return PARSE_JSON_STR_FAIL;
    }

    JSON_STR_JUDGMENT(obj, modeval, keyInfo, "keyInfo", error_str)
    JSON_STR_JUDGMENT2(obj, modeval, specification, "specification", error_str)
    JSON_STR_JUDGMENT2(obj, modeval, latitudeLongitude, "latitudeLongitude", error_str)
    JSON_STR_JUDGMENT2(obj, modeval, srcHash, "srcHash", error_str)
    JSON_STR_JUDGMENT2(obj, modeval, uRL3rd, "uRL3rd", error_str)
    return PARSE_JSON_SUCCESS;
}

UniValue BasicObject::ToJsonObject() const
{
    UniValue obj(UniValue::VOBJ);
    if(!IsNull())
    {
        UniValue arr(UniValue::VARR);
        for(std::vector<std::string>::const_iterator it = objectID.begin(); it != objectID.end(); ++it)
            arr.push_back(it->c_str());
        obj.push_back(Pair("objectID", arr));
        obj.push_back(Pair("utcTime", Convert2Str(utcTime)));
        obj.push_back(Pair("keyInfo", keyInfo));
        obj.push_back(Pair("latitudeLongitude", latitudeLongitude));
        obj.push_back(Pair("specification", specification));
        obj.push_back(Pair("srcHash", srcHash));
        obj.push_back(Pair("uRL3rd", uRL3rd));
    }
    return obj;
}

////////////////////////////////////////////////////////////////////////////////
CBullockChainCompress::CBullockChainCompress(uint32_t uiCompressMethod)
{
    SetNull();

    uiFlag |= BULLOCKCHAIN_BLOCK_COMPRESS_FLAG;

    switch(uiCompressMethod & BULLOCKCHAIN_BLOCK_COMPRESS_METHOD_MASK)
    {
        case BULLOCKCHAIN_BLOCK_COMPRESS_ZIP:
        {
            compressObj = new CZLIBCompress();
            uiFlag += BULLOCKCHAIN_BLOCK_COMPRESS_ZIP;
            break;
        }
        case BULLOCKCHAIN_BLOCK_COMPRESS_LZ4:
        {
            compressObj = new CLZ4Compress();
            uiFlag += BULLOCKCHAIN_BLOCK_COMPRESS_LZ4;
            break;
        }
        case BULLOCKCHAIN_BLOCK_COMPRESS_SNAPPY:
        {
            compressObj = new CSnappyCompress();
            uiFlag += BULLOCKCHAIN_BLOCK_COMPRESS_SNAPPY;
            break;
        }
        default:
        {
            uiFlag&= ~BULLOCKCHAIN_BLOCK_COMPRESS_FLAG;
            break;
        }
    }
}

CBullockChainCompress::~CBullockChainCompress(void)
{
    if(compressObj)
    {
        delete compressObj;
        compressObj = NULL;
    }
}

void CBullockChainCompress::SetNull()
{
    uiFlag = 0;
    compressObj = NULL;
}

CCompressAlgorithmBase* CBullockChainCompress::GetObject() const
{
    return compressObj;
}

uint32_t CBullockChainCompress::GetFlag() const
{
    return uiFlag;
}

////////////////////////////////////////////////////////////////////////////////
BullockChainObject::BullockChainObject()
{
    SetNull();
}

BullockChainObject::BullockChainObject(const BullockChainObject& bullockchainObject)
{
    SetNull();
    objectID_F = bullockchainObject.objectID_F;
    flag       = bullockchainObject.flag;
    utcTime    = bullockchainObject.utcTime;
    markList   = bullockchainObject.markList;
    markHash   = bullockchainObject.markHash;
}

void BullockChainObject::SetNull()
{
    nVersion = CURRENT_VERSION;
    objectID_F.clear();
    flag = -1;
    utcTime = 0;
    markList.clear();
    markHash.clear();
}

bool BullockChainObject::IsNull() const
{
    return objectID_F.empty();
}

std::string BullockChainObject::ToJsonString() const
{
    if(IsNull())
        return std::string();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("objectID_F", objectID_F));
    obj.push_back(Pair("flag", Convert2Str(flag)));
    obj.push_back(Pair("utcTime", Convert2Str(utcTime)));

    UniValue arr(UniValue::VARR);
    for(std::vector<BasicObject>::const_iterator it = markList.begin(); it != markList.end(); ++it)
        arr.push_back(it->ToJsonObject());

    obj.pushKV("markList", arr);
    obj.push_back(Pair("markHash", markHash));
    return obj.write();
}

UniValue BullockChainObject::ToJsonObject() const
{
    UniValue obj(UniValue::VOBJ);
    if(!IsNull())
    {
        obj.push_back(Pair("objectID_F", objectID_F));
        obj.push_back(Pair("flag", Convert2Str(flag)));
        obj.push_back(Pair("utcTime", Convert2Str(utcTime)));

        UniValue arr(UniValue::VARR);
        for(std::vector<BasicObject>::const_iterator it = markList.begin(); it != markList.end(); ++it)
            arr.push_back(it->ToJsonObject());

        obj.pushKV("markList", arr);
        obj.push_back(Pair("markHash", markHash));
    }
    return obj;
}

char* BullockChainObject::CompressJsonString(uint32_t uiCompressMethod, uint32_t *pCompDataSize, uint32_t* pTotolSize) const
{
    int ret = 0;
    CBullockChainCompress BullockChainCompress(uiCompressMethod);

    if(NULL == BullockChainCompress.GetObject())
        return NULL;

    CCompressAlgorithmBase *compressObj = BullockChainCompress.GetObject();
    uint32_t  uiContentFlags, uiOriginalLength, uiCompressedLength;
    uiContentFlags = uiOriginalLength = uiCompressedLength = 0;
    uiContentFlags = BullockChainCompress.GetFlag();

    std::string jsonStr = ToJsonString();
    size_t str_len = jsonStr.length();

    *pCompDataSize = compressObj->GetMaxCompSize(str_len);

    uint32_t uiBullockChainHeaderSize = sizeof(*pTotolSize) + sizeof(uiContentFlags) + sizeof(uiOriginalLength) + sizeof(uiCompressedLength);

    char* buffer = new char [*pCompDataSize + uiBullockChainHeaderSize];

    ret = compressObj->Compress(buffer + uiBullockChainHeaderSize, (int *)pCompDataSize, jsonStr.c_str(), str_len);
    if(ret)
    {
        delete [] buffer;
        buffer = NULL;
        return NULL;
    }

    *pTotolSize = *pCompDataSize + uiBullockChainHeaderSize - sizeof(*pTotolSize);
    uiCompressedLength = *pCompDataSize;
    uiOriginalLength = jsonStr.length();

    uint32_t offset = 0;
    memcpy(buffer + offset, pTotolSize, sizeof(*pTotolSize));
    offset += sizeof(*pTotolSize);
    memcpy(buffer + offset, &uiContentFlags, sizeof(uiContentFlags));
    offset += sizeof(uiContentFlags);
    memcpy(buffer + offset, &uiOriginalLength, sizeof(uiOriginalLength));
    offset += sizeof(uiOriginalLength);
    memcpy(buffer + offset, &uiCompressedLength, sizeof(uiCompressedLength));

    return buffer;
}

char* BullockChainObject::DecompressJsonString(uint32_t uiCompressMethod, char* str, uint32_t uiOriginalLength, uint32_t uiCompressedLength)
{
    CBullockChainCompress BullockChainCompress(uiCompressMethod);
    if(NULL == BullockChainCompress.GetObject())
        return NULL;

    CCompressAlgorithmBase *compressObj = BullockChainCompress.GetObject();

    char *ori = new char [uiOriginalLength + 1];

    compressObj->Decompress(ori, (int)uiOriginalLength, str, (int)uiCompressedLength);

    ori[uiOriginalLength] = '\0';
    return ori;
}


BullockChainObject& BullockChainObject::operator=(const BullockChainObject& other)
{
    if(this == &other)
        return *this;

    SetNull();
    objectID_F = other.objectID_F;
    flag       = other.flag;
    utcTime    = other.utcTime;
    markList   = other.markList;
    markHash   = other.markHash;

    return *this;
}

////////////////////////////////////////////////////////////////////////////////
COutPoint::COutPoint()
{
    SetNull();
}

COutPoint::COutPoint(uint256 hashIn, EnumTx nTypeIn, uint32_t nIn)
{
    hash = hashIn;
    nType = (int32_t)nTypeIn;
    n = nIn;
}

void COutPoint::SetNull()
{
    hash.SetNull();
    nType = (int32_t)EnumTx::TX_NULL;
    n = (uint32_t) -1;
}

bool COutPoint::IsNull() const
{
    return (hash.IsNull() && nType == (int32_t)EnumTx::TX_NULL && n == (uint32_t) -1);
}

bool COutPoint::IsTokenType() const
{
    return ((int32_t)EnumTx::TX_TOKEN == nType);
}

////////////////////////////////////////////////////////////////////////////////
CTxIn::CTxIn()
{
    nSequence = SEQUENCE_FINAL;
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

////////////////////////////////////////////////////////////////////////////////
CTxOut::CTxOut()
{
    SetNull();
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

void CTxOut::SetNull()
{
    nValue = -1;
    scriptPubKey.clear();
}

bool CTxOut::IsNull() const
{
    return (nValue == -1);
}

////////////////////////////////////////////////////////////////////////////////
CGasToken::CGasToken() : vin(), vout() {}
CGasToken::CGasToken(const CMutableGasToken& gas) : strPayCurrencySymbol(gas.strPayCurrencySymbol), vin(gas.vin), vout(gas.vout) {}
CGasToken::CGasToken(CMutableGasToken& gas) : strPayCurrencySymbol(gas.strPayCurrencySymbol), vin(std::move(gas.vin)), vout(std::move(gas.vout)) {}

bool CGasToken::HasWitness() const
{
    for(size_t i = 0; i < vin.size(); i++)
    {
        if(!vin[i].scriptWitness.IsNull())
            return true;
    }
    return false;
}

bool CGasToken::Empty() const
{
    return (vin.empty() && vout.empty() && strPayCurrencySymbol.empty());
}

CMutableGasToken::CMutableGasToken() : vin(), vout() {}
CMutableGasToken::CMutableGasToken(const CGasToken& gas) : strPayCurrencySymbol(gas.strPayCurrencySymbol), vin(gas.vin), vout(gas.vout) {}

bool CMutableGasToken::HasWitness() const
{
    for(size_t i = 0; i < vin.size(); i++)
    {
        if(!vin[i].scriptWitness.IsNull())
            return true;
    }
    return false;
}

void CMutableGasToken::clear()
{
    strPayCurrencySymbol.clear();
    vin.clear();
    vout.clear();
}

bool CMutableGasToken::Empty() const
{
    return (vin.empty() && vout.empty() && strPayCurrencySymbol.empty());
}

////////////////////////////////////////////////////////////////////////////////
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), nBusinessType(BUSINESSTYPE_TRANSACTION), tokenParam(), bullockchainObject(), strPayCurrencySymbol(GlobalProfile::strPayCurrencySymbol), nLockTime(0), gasToken(), txExch(NULL) {}

CTransaction::CTransaction(const CMutableTransaction& tx)
    : nVersion(tx.nVersion)
    , nBusinessType(tx.nBusinessType)
    , tokenParam(tx.tokenParam)
    , bullockchainObject(tx.bullockchainObject)
    , strPayCurrencySymbol(tx.strPayCurrencySymbol)
    , vin(tx.vin)
    , vout(tx.vout)
    , nLockTime(tx.nLockTime)
    , gasToken(tx.gasToken)
    , hash(ComputeHash())
    , strAttach(tx.strAttach)
    , txExch((tx.txExch == NULL) ? NULL : MakeTransactionRef(std::move((CMutableTransaction)(*tx.txExch))))
, theOtherHash(tx.theOtherHash)
{
}

CTransaction::CTransaction(CMutableTransaction &&tx)
    : nVersion(tx.nVersion)
    , nBusinessType(tx.nBusinessType)
    , tokenParam(tx.tokenParam)
    , bullockchainObject(tx.bullockchainObject)
    , strPayCurrencySymbol(tx.strPayCurrencySymbol)
    , vin(std::move(tx.vin))
    , vout(std::move(tx.vout))
    , nLockTime(tx.nLockTime)
    , gasToken(tx.gasToken)
    , strAttach(std::move(tx.strAttach))
    , hash(ComputeHash())
    , txExch((tx.txExch == NULL) ? NULL : MakeTransactionRef(std::move((CMutableTransaction)(*tx.txExch))))
, theOtherHash(tx.theOtherHash)
{
}

bool CTransaction::IsNull() const
{
    return vin.empty() && vout.empty();
}

uint256 CTransaction::GetHash() const
{
    return hash;
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::GetWitnessHash() const
{
    if(!HasWitness())
        return GetHash();
    return SerializeHash(*this, SER_GETHASH, 0);
}

bool CTransaction::HasWitness() const
{
    for(size_t i = 0; i < vin.size(); i++)
    {
        if(!vin[i].scriptWitness.IsNull())
            return true;
    }
    return false;
}

bool CTransaction::IsTokenFlag() const
{
    return (TOKEN_TX == tokenParam.nTokenType);
}

int32_t CTransaction::IsExchangeType() const
{
    return (nBusinessType & BUSINESSTYPE_EXCHANGE);
}

int32_t CTransaction::IsExchangeEndFlag() const
{
    return (nBusinessType & BUSINESSTYPE_EXCHANGE_END);
}

int32_t CTransaction::IsExchangeSingle() const
{
    return (nBusinessType & BUSINESSTYPE_EXCHANGE_SINGLE);
}

int32_t CTransaction::IsRevokecrlType() const
{
    return (nBusinessType & BUSINESSTYPE_REVOKECRT);
}

int32_t CTransaction::GetBusinessType() const
{
    return (nBusinessType & (0xFF));
}

int32_t CTransaction::GetSubType() const
{
    return (nBusinessType & 0XFFFFFF00);
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nBusinessType(BUSINESSTYPE_TRANSACTION), tokenParam(), bullockchainObject(), strPayCurrencySymbol(GlobalProfile::strPayCurrencySymbol), nLockTime(0), gasToken(), txExch(NULL) {}

CMutableTransaction::CMutableTransaction(const CTransaction& tx)
    : nVersion(tx.nVersion)
    , nBusinessType(tx.nBusinessType)
    , tokenParam(tx.tokenParam)
    , bullockchainObject(tx.bullockchainObject)
    , strPayCurrencySymbol(tx.strPayCurrencySymbol)
    , vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), gasToken(tx.gasToken)
    , strAttach(tx.strAttach)
    , txExch((tx.txExch == NULL) ? NULL : MakeMutableTransactionRef(std::move((CTransaction)(*tx.txExch))))
, theOtherHash(tx.theOtherHash)
{
}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

bool CMutableTransaction::HasWitness() const
{
    for(size_t i = 0; i < vin.size(); i++)
    {
        if(!vin[i].scriptWitness.IsNull())
            return true;
    }
    return false;
}

int32_t CMutableTransaction::GetBusinessType() const
{
    return (nBusinessType & (0xFF));
}

void CMutableTransaction::SetBusinessType(int32_t nBusinessTypeIn)
{
    nBusinessType &= 0XFFFFFF00;
    nBusinessType |= nBusinessTypeIn;
}

void CMutableTransaction::SetExchangeType(int32_t nExchangeType)
{
    nBusinessType |= nExchangeType;
}

int32_t CMutableTransaction::IsExchangeType() const
{
    return (nBusinessType & BUSINESSTYPE_EXCHANGE);
}

int32_t CMutableTransaction::IsExchangeEndFlag() const
{
    return (nBusinessType & BUSINESSTYPE_EXCHANGE_END);
}

int32_t CMutableTransaction::IsExchangeSingle() const
{
    return (nBusinessType & BUSINESSTYPE_EXCHANGE_SINGLE);
}

int32_t CMutableTransaction::GetSubType() const
{
    return (nBusinessType & 0XFFFFFF00);
}
