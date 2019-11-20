// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "tinyformat.h"
#include "univalue.h"
#include "utilstrencodings.h"

const std::string CURRENCY_UNIT = "DALI";
//const std::string CURRENCY_UNIT = "ZXT";
const std::string GAS_CURRENCY_UNIT = "GAS";

CAmount AmountFromValue(const UniValue& value, const std::string& strCurrencySymbol)
{
    if (!value.isNum() && !value.isStr())
        throw std::ios_base::failure("Amount is not a number or string");

    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), strCurrencySymbol == "GAS" ? 0 : 8, &amount))
        throw std::ios_base::failure("Invalid amount");

    if (strCurrencySymbol == "DALI")
    {
        if (!MoneyRange(amount))
            throw std::ios_base::failure("DALI amount out of range");
    }
    else
    {
        if (!TokenMoneyRange(amount))
            throw std::ios_base::failure("Token amount out of range");
    }
    return amount;
}

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize > 0)
        nSatoshisPerK = nFeePaid * 1000 / nSize;
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nBytes_) const
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    CAmount nFee = nSatoshisPerK * (nSize / 1000 + ((nSize % 1000) > 0 ? 1 : 0));
    if (nFee <= 0) {
        nFee = nSatoshisPerK;
    }

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%08d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}


CFeeRate_Gas::CFeeRate_Gas(const CAmount& nFeePaid, size_t nBytes_)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize > 0)
        nSatoshisPerK = nFeePaid * 1000 / nSize;
    else
        nSatoshisPerK = 0;
}


std::string CFeeRate_Gas::ToString() const
{
    return strprintf("%d %s/kB", nSatoshisPerK, GAS_CURRENCY_UNIT);
}
