// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include "transaction.h"

#include <vector>
#include <stdint.h>
#include <string>
#include "pubkey.h"

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Support segregated witness
    //
    SCRIPT_VERIFY_WITNESS = (1U << 11),

    // Making v1-v16 witness program non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),

    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Public keys in segregated witness scripts must be compressed
    //
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 15),
};

struct PrecomputedTransactionData
{
    uint256 hashPrevouts, hashSequence, hashOutputs;

    PrecomputedTransactionData(const CTransaction& tx);
};

enum SigVersion
{
    SIGVERSION_BASE = 0,
    SIGVERSION_WITNESS_V0 = 1,
};

uint256 SignatureHash(const CScript &scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, EnumTx nInType, const PrecomputedTransactionData* cache = NULL);

class BaseSignatureChecker
{
public:
    virtual bool CheckContract(const std::vector<unsigned char>& vchContractHash, std::vector<unsigned char>& vchContractAddress) const
    {
         return false;
    }

    virtual ~BaseSignatureChecker() {}
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const CTransaction* txTo;
    unsigned int nIn;
    EnumTx nInType;
    const CAmount amount;
    const PrecomputedTransactionData* txdata;

public:
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, EnumTx nInTypeIn, const CAmount& amountIn) : txTo(txToIn), nIn(nInIn), nInType(nInTypeIn), amount(amountIn), txdata(NULL) {}
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, EnumTx nInTypeIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn) : txTo(txToIn), nIn(nInIn), nInType(nInTypeIn), amount(amountIn), txdata(&txdataIn) {}
    EnumTx GetInType() const { return nInType;}
    bool CheckContract(const std::vector<unsigned char>& vchContractHash, std::vector<unsigned char>& vchContractAddress) const;
};

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion);

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags);

namespace {
class CExchangeTransactionSignatureSerializer {
private:
    const CTransaction& txTo;  //!< reference to the spending transaction (the one being serialized)


public:
    CExchangeTransactionSignatureSerializer(const CTransaction &txToIn) : txTo(txToIn) {}

    /** Serialize an input of txTo */
    template<typename S>
        void SerializeInput(S &s, unsigned int nInput) const {
            // Serialize the prevout
            ::Serialize(s, txTo.vin[nInput].prevout);
            ::Serialize(s, txTo.vin[nInput].nSequence);
        }

    /** Serialize an input of txTo */
    template<typename S>
        void SerializeGasInput(S &s, unsigned int nInput) const {
            ::Serialize(s, txTo.gasToken.vin[nInput].prevout);
            ::Serialize(s, txTo.gasToken.vin[nInput].nSequence);
        }


    /** Serialize an output of txTo */
    template<typename S>
        void SerializeOutput(S &s, unsigned int nOutput) const {
            ::Serialize(s, txTo.vout[nOutput]);
        }

    /** Serialize an output of txTo */
    template<typename S>
        void SerializeGasOutput(S &s, unsigned int nOutput) const {
            ::Serialize(s, txTo.gasToken.vout[nOutput]);
        }

    template<typename S>
        void SerializeTokenParam(S &s) const {
            ::Serialize(s, txTo.tokenParam.nTokenType);
            ::Serialize(s, txTo.tokenParam.nAdditional);
            ::Serialize(s, txTo.tokenParam.nValueLimit);
            ::Serialize(s, txTo.tokenParam.vTokenIcon);
        }

    /** Serialize txTo */
    template<typename S>
        void Serialize(S &s) const {
            // Serialize nVersion
            ::Serialize(s, txTo.nVersion);

            // Serialize vin
            unsigned int nInputs = 0;

            // Serialize vout
            unsigned int nOutputs = 0;

            nInputs = txTo.vin.size();
            ::WriteCompactSize(s, nInputs);

            for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                SerializeInput(s, nInput);

            nOutputs = txTo.vout.size();
            ::WriteCompactSize(s, nOutputs);

            for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                SerializeOutput(s, nOutput);

            // Serialize nLockTime
            ::Serialize(s, txTo.nLockTime);

            ::Serialize(s, txTo.nBusinessType&~BUSINESSTYPE_EXCHANGE_SINGLE);
            SerializeTokenParam(s);
            ::Serialize(s, txTo.strPayCurrencySymbol);
            ::Serialize(s, txTo.gasToken.strPayCurrencySymbol);
            ::Serialize(s, txTo.strAttach);

            if (BUSINESSTYPE_DATAWRITE == txTo.GetBusinessType()) {
                ::Serialize(s, txTo.bullockchainObject);
            }

            if (BUSINESSTYPE_TOKEN == txTo.GetBusinessType()) {

                nInputs = txTo.gasToken.vin.size();
                ::WriteCompactSize(s, nInputs);

                for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                    SerializeGasInput(s, nInput);

                nOutputs = txTo.gasToken.vout.size();
                ::WriteCompactSize(s, nOutputs);

                for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                    SerializeGasOutput(s, nOutput);

            }

        }
};

}

#endif // BITCOIN_SCRIPT_INTERPRETER_H
