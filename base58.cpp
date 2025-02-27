// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include "hash.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>
#include "utilstrencodings.h"

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 733 /1000 + 1; // log(58) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char* ch = strchr(pszBase58, *psz);
        if (ch == NULL)
            return false;
        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    int size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
    std::vector<unsigned char> b58(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

CBase58Data::CBase58Data()
{
    vchVersion.clear();
    vchData.clear();
}

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const void* pdata, size_t nSize)
{
    vchVersion = vchVersionIn;
    vchData.resize(nSize);
    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const unsigned char* pbegin, const unsigned char* pend)
{
    SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
}

bool CBase58Data::SetString(const char* psz, unsigned int nVersionBytes)
{
    std::vector<unsigned char> vchTemp;
    bool rc58 = DecodeBase58Check(psz, vchTemp);
    if ((!rc58) || (vchTemp.size() < nVersionBytes)) {
        vchData.clear();
        vchVersion.clear();
        return false;
    }
    vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
    vchData.resize(vchTemp.size() - nVersionBytes);
    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());
    memory_cleanse(&vchTemp[0], vchTemp.size());
    return true;
}

bool CBase58Data::SetString(const std::string& str)
{
    return SetString(str.c_str());
}

std::string CBase58Data::ToString() const
{
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase58Check(vch);
}

int CBase58Data::CompareTo(const CBase58Data& b58) const
{
    if (vchVersion < b58.vchVersion)
        return -1;
    if (vchVersion > b58.vchVersion)
        return 1;
    if (vchData < b58.vchData)
        return -1;
    if (vchData > b58.vchData)
        return 1;
    return 0;
}

bool CBase58Data::IsSinglePointContract() const
{
    return vchVersion == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ? true : false;
}


namespace
{
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddress* addr;

public:
    CBitcoinAddressVisitor(CBitcoinAddress* addrIn) : addr(addrIn) {}

    bool operator()(const CKeyID& id) const { return addr->Set(id); }
    bool operator()(const CScriptID& id) const { return addr->Set(id); }
    bool operator()(const CContractAddress& address) const { return addr->Set(address); }
    bool operator()(const CContractTXScript& script) const { return addr->Set(script); }
    bool operator()(const CRealNameAddress& address) const { return addr->Set(address); }
    bool operator()(const CNoDestination& no) const { return false; }
};

} // anon namespace

bool CRealNameAddress::Set(const CKeyID& id)
{
    SetData(Params().Base58Prefix(CChainParams::REALNAME_ADDRESS), &id, 20);
    return true;
}

bool CRealNameAddress::IsValid() const
{
    return IsValid(Params());
}

bool CRealNameAddress::IsValid(const CChainParams &params) const
{
    bool fCorrectSize = vchData.size() == 20;
    bool fKnownVersion = vchVersion == params.Base58Prefix(CChainParams::REALNAME_ADDRESS);
    return fCorrectSize && fKnownVersion;
}

bool CRealNameAddress::GetKeyID(CKeyID& keyID) const
{
    if (!IsValid())
        return false;

    if (vchVersion == Params().Base58Prefix(CChainParams::REALNAME_ADDRESS))
    {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        keyID = CKeyID(id);
    }
    else {
        return false;
    }

    return true;
}

bool CBitcoinAddress::Set(const CKeyID& id)
{
    SetData(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS), &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CScriptID& id)
{
    SetData(Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS), &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CContractAddress& addr)
{
    if (!addr.IsValid())
        return false;

    vchVersion = addr.Version();
    vchData = addr.Data();

    return true;
}

bool CBitcoinAddress::Set(const CContractTXScript& script)
{
    if (CChainParams::Base58Type::SPA_CONTRACT_ADDRESS != script.type) {
        return false;
    }
    CContractAddress contractAddress = CContractAddress(script.type, script.keyID, script.contractID);
    return CBitcoinAddress::Set(contractAddress);
}

bool CBitcoinAddress::Set(const CRealNameAddress& addr)
{
    if (!addr.IsValid())
        return false;

    vchVersion = addr.Version();
    vchData = addr.Data();
    return true;
}

bool CBitcoinAddress::Set(const CTxDestination& dest)
{
    return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
}

bool CBitcoinAddress::IsValid() const
{
    return IsValid(Params());
}

bool CBitcoinAddress::IsValid(const CChainParams& params) const
{
    if (vchData.size() == 20) {
        return vchVersion == params.Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::SCRIPT_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::REALNAME_ADDRESS);
    }
    // contract address
    else if (vchData.size() == 40) {
        return vchVersion == params.Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
               vchVersion == params.Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS);
    }
    return false;
}

CTxDestination CBitcoinAddress::Get() const
{
    if (!IsValid())
        return CNoDestination();

    if (vchData.size() == 20) {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        if (vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
            vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
            return CKeyID(id);
        else if (vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS))
            return CScriptID(id);
        else if (vchVersion == Params().Base58Prefix(CChainParams::REALNAME_ADDRESS))
            return CRealNameAddress(id);
    }
    // contract address
    else if (vchData.size() == 40) {
        if (vchVersion == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ||
            vchVersion == Params().Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS) ||
            vchVersion == Params().Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS) ||
            vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
            vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
            vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS))
        {
            std::vector<unsigned char> vchSetData;
            vchSetData.resize(41);
            vchSetData[0] = vchVersion[0];
            memcpy(&vchSetData[1], &vchData[0], vchData.size());

            return CContractAddress(vchSetData);
        }
    }

    return CNoDestination();
}

bool CBitcoinAddress::GetKeyID(CKeyID& keyID) const
{
    if (!IsValid())
        return false;

    if (vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::REALNAME_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
        vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS))
    {
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        keyID = CKeyID(id);
    }
    else {
        return false;
    }

    return true;
}

bool CBitcoinAddress::IsScript() const
{
    return IsValid() && vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
}

bool CBitcoinAddress::IsBasicAddress() const
{
    return IsValid() && vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS);
}

bool CBitcoinAddress::IsBitcoinAddress() const
{
    return IsValid() && (vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS));
}

bool CBitcoinAddress::IsContractAddress() const
{
    return IsValid() && (vchVersion == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS));
}

bool CBitcoinAddress::IsRealNameAddress() const
{
    return IsValid() && (vchVersion == Params().Base58Prefix(CChainParams::REALNAME_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS));
}

void CBitcoinSecret::SetKey(const CKey& vchSecret)
{
    assert(vchSecret.IsValid());
    SetData(Params().Base58Prefix(CChainParams::SECRET_KEY), vchSecret.begin(), vchSecret.size());
    if (vchSecret.IsCompressed())
        vchData.push_back(1);
}

CKey CBitcoinSecret::GetKey()
{
    CKey ret;
    assert(vchData.size() >= 32);
    ret.Set(vchData.begin(), vchData.begin() + 32, vchData.size() > 32 && vchData[32] == 1);
    return ret;
}

bool CBitcoinSecret::IsValid() const
{
    bool fExpectedFormat = vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1);
    bool fCorrectVersion = vchVersion == Params().Base58Prefix(CChainParams::SECRET_KEY);
    return fExpectedFormat && fCorrectVersion;
}

bool CBitcoinSecret::SetString(const char* pszSecret)
{
    return CBase58Data::SetString(pszSecret) && IsValid();
}

bool CBitcoinSecret::SetString(const std::string& strSecret)
{
    return SetString(strSecret.c_str());
}

CContractAddress::CContractAddress(const std::vector<unsigned char> &data)
{
    if (data.size() != 41)
        return;

    vchVersion.assign(data.begin(), data.begin() + 1);

    if (!(vchVersion == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ||
          vchVersion == Params().Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS) ||
          vchVersion == Params().Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS) ||
          vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
          vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
          vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS)))
    {
        vchVersion.clear();
        return;
    }

    vchData.resize(data.size() - 1);
    if (!vchData.empty())
        memcpy(&vchData[0], &data[1], vchData.size());
}

bool CContractAddress::Set(CChainParams::Base58Type type, const CKeyID &id, const CContractCodeID &contractID)
{
    if (type < 0 || type > CChainParams::Base58Type::MAX_BASE58_TYPES)
        return false;

    std::vector<unsigned char> vchTemp;
    vchTemp.resize(40);
    memcpy(&vchTemp[0], &id, 20);
    memcpy(&vchTemp[20], &contractID, 20);
    // std::cout << "type: "<< type << " vchTemp:" << HexStr(vchTemp).c_str() << std::endl;
    SetData(Params().Base58Prefix(type), &vchTemp[0], 40);

    return true;
}

bool CContractAddress::Set(const std::vector<unsigned char> vchVersion, const CKeyID &id, const CContractCodeID &contractID)
{
    std::vector<unsigned char> vchTemp;
    vchTemp.resize(40);
    memcpy(&vchTemp[0], &id, 20);
    memcpy(&vchTemp[20], &contractID, 20);

    SetData(vchVersion, &vchTemp[0], 40);
    return true;
}

bool CContractAddress::IsValid() const
{
    return IsValid(Params());
}

bool CContractAddress::IsValid(const CChainParams &params) const
{
    bool fCorrectSize = vchData.size() == 40;
    bool fKnownVersion = vchVersion == params.Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS);
    return fCorrectSize && fKnownVersion;
}

bool CContractAddress::IsRealNameContract() const
{
    bool fCorrectSize = vchData.size() == 40;
    bool fRealNameVersion = vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS) ||
                         vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS);
    return fCorrectSize && fRealNameVersion;
}

bool CContractAddress::GetVersion(std::vector<unsigned char> &version) const
{
    if (!IsValid())
        return false;

    version = vchVersion;
    return true;
}

bool CContractAddress::GetKeyID(CKeyID& keyID) const
{
    if (!IsValid())
        return false;

    uint160 id;
    memcpy(&id, &vchData[0], 20);
    keyID = CKeyID(id);
    return true;
}

bool CContractAddress::GetOriginalAddr(std::string &originaladdr)
{
     if (!IsValid())
        return false;

    uint160 id;
    memcpy(&id, &vchData[0], 20);
    if (IsRealNameContract())
    {
        SetData(Params().Base58Prefix(CChainParams::REALNAME_ADDRESS), &id, 20);
    }
    else
    {
        SetData(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS), &id, 20);
    }
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    originaladdr = EncodeBase58Check(vch);
    return true;
}

bool CContractAddress::GetContractID(CContractCodeID &ContractID) const
{
    if (!IsValid())
        return false;

    uint160 id;
    memcpy(&id, &vchData[20], 20);
    ContractID = CContractCodeID(id);
    return true;
}

unsigned char CContractAddress::GetBase58prefix()
{
    if (vchData.size() == 40) {
        if (vchVersion == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS)) {
            return CChainParams::SPA_CONTRACT_ADDRESS;
        }
        else if (vchVersion == Params().Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS)) {
            return CChainParams::WNS_CONTRACT_ADDRESS;
        }
        else if (vchVersion == Params().Base58Prefix(CChainParams::WNA_CONTRACT_ADDRESS)) {
            return CChainParams::WNA_CONTRACT_ADDRESS;
        }
        else if (vchVersion == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS)) {
            return CChainParams::REALNAME_SPA_CONTRACT_ADDRESS;
        }
        else if (vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS)) {
            return CChainParams::REALNAME_WNS_CONTRACT_ADDRESS;
        }
        else if (vchVersion == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS)) {
            return CChainParams::REALNAME_WNA_CONTRACT_ADDRESS;
        }
    }

    return 0;
}

std::vector<unsigned char> CContractAddress::GetData() const
{
    std::vector<unsigned char> vchDataOut;
    if (IsValid()) {
        vchDataOut.resize(41);
        vchDataOut[0] = vchVersion[0];
        memcpy(&vchDataOut[1], &vchData[0], vchData.size());
    }
    return vchDataOut;
}

std::ostream& operator<<(std::ostream& _out, CBase58Data const& _b58)
{
    _out << "Address: " << _b58.ToString().c_str() << std::endl;
    return _out;
}
