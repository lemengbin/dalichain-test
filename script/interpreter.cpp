// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "transaction.h"

#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "pubkey.h"
#include "script/script.h"
#include "uint256.h"
#include "sync.h"
#include "base58.h"

#include <string.h>
#include <univalue.h>
// #include <boost/foreach.hpp>
// #include <boost/assign/list_of.hpp>
#include "utilstrencodings.h"
#include "ca/ca.h"
#include "ca/camempool.h"

#include "contract/contractcode.h"
#include "attachinfo.h"

using namespace std;

//extern CCaMempool g_caMempool;

typedef vector<unsigned char> valtype;

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(vector<valtype>& stack)
{
    if (stack.empty())
        throw runtime_error("popstack(): stack empty");
    stack.pop_back();
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const CScriptNum bnFalse(0);
    static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    vector<bool> vfExec;
    vector<valtype> altstack;

    if (script.size() > MAX_SCRIPT_SIZE)
        return false;

    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;

    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return false;
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return false;

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
                return false;

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return false; // Disabled opcodes.

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return false;
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return false;

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return false;

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return false;
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return false;

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return false;

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    break;
                }

                // check real-name transaction.
                case OP_CHECKREALNAMESIG:
                {
                    // (sig pubkeyhash -- bool)
                    if (stack.size() < 2)
                    {
                        return false;
                    }
                    popstack(stack);
                    //popstack(stack);
                }
                break;

                case OP_NOP1: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return false;
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return false;
                        valtype& vch = stacktop(-1);
                        if (sigversion == SIGVERSION_WITNESS_V0 && (flags & SCRIPT_VERIFY_MINIMALIF)) {
                            if (vch.size() > 1)
                                return false;
                            if (vch.size() == 1 && vch[0] != 1)
                                return false;
                        }
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return false;
                    vfExec.back() = !vfExec.back();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return false;
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return false;
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return false;
                }
                break;

                case OP_RETURN:
                {
                    return false;
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return false;
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return false;
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return false;
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return false;
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return false;
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return false;
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return false;
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return false;
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return false;
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return false;
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return false;
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return false;
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return false;
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return false;
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return false;
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return false;
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return false;
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return false;
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return false;
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;


                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return false;
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return false;
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return false;
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return false;
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return false;
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH160)
                    {
                        if (script.IsRealNameContract())
                            break;
                        else
                            CHash160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    }
                    else if (opcode == OP_HASH256)
                        CHash256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return false;

                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);
                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    if (sigversion == SIGVERSION_BASE) {
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }

                    popstack(stack);
                    popstack(stack);
                    bool fSuccess = true;
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    if ((int)stack.size() < i)
                        return false;

                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return false;
                    nOpCount += nKeysCount;
                    if (nOpCount > MAX_OPS_PER_SCRIPT)
                        return false;
                    int ikey = ++i;
                    // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    int ikey2 = nKeysCount + 2;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return false;

                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return false;
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return false;

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig-k);
                        if (sigversion == SIGVERSION_BASE) {
                            scriptCode.FindAndDelete(CScript(vchSig));
                        }
                    }

                    bool fSuccess = true;
                    while (fSuccess && nSigsCount > 0)
                    {
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);

                        // Check signature
                        bool fOk = true;
                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }

                    // Clean up stack of actual arguments
                    while (i-- > 1) {
                        // If the operation failed, we require that all signatures must be empty vector
                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
                            return false;
                        if (ikey2 > 0)
                            ikey2--;
                        popstack(stack);
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return false;
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                        return false;
                    popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;

                // contract
                case OP_CHECKCONTRACT:
                {
                    // (contractaddress -- bool)
                    if (stack.size() < 1) {
                        return false;
                    }

                    valtype& vchContractHash = stacktop(-1);
                    std::vector<unsigned char> vchContractAddress;
                    // Check contract tx info
                    bool fOk = checker.CheckContract(vchContractHash, vchContractAddress);
                    if (!fOk) {
                        return false;
                    }

                    popstack(stack);
                    if (vchContractAddress[0] == Params().Base58Prefix(CChainParams::SPA_CONTRACT_ADDRESS)[0] ||
                        vchContractAddress[0] == Params().Base58Prefix(CChainParams::WNS_CONTRACT_ADDRESS)[0] ||
                        vchContractAddress[0] == Params().Base58Prefix(CChainParams::REALNAME_SPA_CONTRACT_ADDRESS)[0] ||
                        vchContractAddress[0] == Params().Base58Prefix(CChainParams::REALNAME_WNS_CONTRACT_ADDRESS)[0] ||
                        vchContractAddress[0] == Params().Base58Prefix(CChainParams::REALNAME_WNA_CONTRACT_ADDRESS)[0]) {
                        stack.push_back(vchContractAddress);
                    }
                }
                break;

                case OP_CONTRACTKEYID:
                {
                    // (contractaddress -- bool)
                    if (stack.size() < 1) {
                        return false;
                    }

                    valtype& vchContractAddress = stacktop(-1);
                    CContractAddress contractAddress(vchContractAddress);
                    if (!contractAddress.IsValid()) {
                        return false;
                    }

                    CKeyID keyID;
                    contractAddress.GetKeyID(keyID);

                    popstack(stack);
                    stack.push_back(valtype(keyID.begin(), keyID.end()));
                }
                break;

                default:
                    return false;
            }

            // Size limits
            if (stack.size() + altstack.size() > 1000)
                return false;
        }
    }
    catch (...)
    {
        return false;
    }

    if (!vfExec.empty())
        return false;

    return true;
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    const CTransaction& txTo;  //!< reference to the spending transaction (the one being serialized)
    const CScript& scriptCode; //!< output script being consumed
    const unsigned int nIn;    //!< input index of txTo being signed
    const EnumTx nInType;
    const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn, EnumTx nInTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn), nInType(nInTypeIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScriptBase());
        else
            SerializeScriptCode(s);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeGasInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.gasToken.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScriptBase());
        else
            SerializeScriptCode(s);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0);
        else
            ::Serialize(s, txTo.gasToken.vin[nInput].nSequence);
    }


    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
            ::Serialize(s, txTo.vout[nOutput]);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeGasOutput(S &s, unsigned int nOutput) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
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

        if (nInType == EnumTx::TX_GAS) {
            nInputs = fAnyoneCanPay ? 1 : txTo.gasToken.vin.size();
            ::WriteCompactSize(s, nInputs);

            for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                SerializeGasInput(s, nInput);
        } else if (nInType == EnumTx::TX_TOKEN) {
            nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
            ::WriteCompactSize(s, nInputs);

            for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                SerializeInput(s, nInput);
        }

        // Serialize vout
        unsigned int nOutputs = 0;

        if (nInType == EnumTx::TX_GAS) {
            nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.gasToken.vout.size());
            ::WriteCompactSize(s, nOutputs);

            for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                SerializeGasOutput(s, nOutput);
        } else if (nInType == EnumTx::TX_TOKEN) {
            nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
            ::WriteCompactSize(s, nOutputs);

            for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                SerializeOutput(s, nOutput);
        }

        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime);


        /*
        AssertLockHeld(cs_main);
        int nHeight = (int)chainActive.Height();
        */

        if (/*nHeight > 400000 || */txTo.nVersion > 3) {
            ::Serialize(s, txTo.nBusinessType);
            SerializeTokenParam(s);
            ::Serialize(s, txTo.strPayCurrencySymbol);
            ::Serialize(s, txTo.gasToken.strPayCurrencySymbol);
            ::Serialize(s, txTo.strAttach);

            if (BUSINESSTYPE_DATAWRITE == txTo.GetBusinessType()) {
                ::Serialize(s, txTo.bullockchainObject);
            }else if (BUSINESSTYPE_TOKEN == txTo.GetBusinessType() && TOKEN_CREATE == txTo.tokenParam.nTokenType) {

                nInputs = txTo.vin.size();
                ::WriteCompactSize(s, nInputs);

                for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                    SerializeInput(s, nInput);

                nOutputs = txTo.vout.size();
                ::WriteCompactSize(s, nOutputs);

                for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                    SerializeOutput(s, nOutput);
            }
        }
    }
};

uint256 GetPrevoutHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].prevout;
    }

    if (BUSINESSTYPE_TOKEN == txTo.GetBusinessType()) {
        for (unsigned int n = 0; n < txTo.gasToken.vin.size(); n++) {
            ss << txTo.gasToken.vin[n].prevout;
        }
    }

    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].nSequence;
    }

    if (BUSINESSTYPE_TOKEN == txTo.GetBusinessType()) {
        for (unsigned int n = 0; n < txTo.gasToken.vin.size(); n++) {
            ss << txTo.gasToken.vin[n].nSequence;
        }
    }

    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vout.size(); n++) {
        ss << txTo.vout[n];
    }

    if (BUSINESSTYPE_TOKEN == txTo.GetBusinessType()) {
        for (unsigned int n = 0; n < txTo.gasToken.vout.size(); n++) {
            ss << txTo.gasToken.vout[n];
        }
    }

    return ss.GetHash();
}

} // anon namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo)
{
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
}

uint256 SignatureHash(const CScript& scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, EnumTx nInType, const PrecomputedTransactionData* cache)
{
    if (sigversion == SIGVERSION_WITNESS_V0) {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;

        if (!(nHashType & SIGHASH_ANYONECANPAY)) {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        }

        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.gasToken.vout.size() && nInType == EnumTx::TX_GAS) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.gasToken.vout[nIn];

            if (BUSINESSTYPE_TOKEN == txTo.GetBusinessType() && TOKEN_CREATE == txTo.tokenParam.nTokenType) {
                for (unsigned int n = 0; n < txTo.vout.size(); n++) {
                    ss << txTo.vout[n];
                }
            }

            hashOutputs = ss.GetHash();
        } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size() && nInType == EnumTx::TX_TOKEN) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;

        ss << txTo.nBusinessType;
        ss << txTo.strPayCurrencySymbol;
        ss << txTo.gasToken.strPayCurrencySymbol;
        ss << txTo.strAttach;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        ss << static_cast<const CScriptBase&>(scriptCode);
        ss << amount;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime;

        ss << txTo.tokenParam.nTokenType;
        ss << txTo.tokenParam.nAdditional;
        ss << txTo.tokenParam.nValueLimit;
        ss << txTo.tokenParam.vTokenIcon;

        if (BUSINESSTYPE_DATAWRITE == txTo.GetBusinessType()) {
            ss << txTo.bullockchainObject;
        }

        // Sighash type
        ss << nHashType;

        return ss.GetHash();
    }

    static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    if (nInType == EnumTx::TX_GAS) {
        if (nIn >= txTo.gasToken.vin.size()) {
            //  nIn out of range
            return one;
        }

        // Check for invalid use of SIGHASH_SINGLE
        if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
            if (nIn >= txTo.gasToken.vout.size()) {
                //  nOut out of range
                return one;
            }
        }
    } else if (nInType == EnumTx::TX_TOKEN) {
        if (nIn >= txTo.vin.size()) {
            //  nIn out of range
            return one;
        }

        // Check for invalid use of SIGHASH_SINGLE
        if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
            if (nIn >= txTo.vout.size()) {
                //  nOut out of range
                return one;
            }
        }
    }

    CHashWriter ss(SER_GETHASH, 0);

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType, nInType);

    // Serialize and hash
    if (txTo.IsExchangeType() && !txTo.IsExchangeSingle())
    {
        if (!txTo.IsExchangeEndFlag()  && txTo.txExch != NULL) {
            CExchangeTransactionSignatureSerializer txTmpExch(*txTo.txExch);
            ss << txTmp << txTmpExch << nHashType;
        }
        else if (txTo.IsExchangeEndFlag()) {
            ss << txTo.theOtherHash << txTmp << nHashType;
        }
    }
    else {
        // ss << txTmp << nHashType;
        ss << txTmp;
        ss << nHashType;
    }

    return ss.GetHash();
}

uint256 GetContractHash(UniValue contractCall)
{
    CHashWriter ss(SER_GETHASH, 0);
    int version = contractCall["version"].get_int();
    ss << version;

    const UniValue& contract = find_value(contractCall, "contract");

    if (!contract.isNull()) {
        std::vector<std::string> veckeys = contract.getKeys();
        std::sort(veckeys.begin(), veckeys.begin() + veckeys.size());

        for (const std::string& key_: veckeys) {
            const UniValue& obj = find_value(contract, key_);
            ss << obj.getValStr();
        }
    }

    const UniValue& request = find_value(contractCall, "request");
    std::vector<std::string> veckeys = request.getKeys();
    std::sort(veckeys.begin(), veckeys.begin() + veckeys.size());

    for (const std::string& key_: veckeys) {
        const UniValue& obj = find_value(request, key_);
        ss << obj.getValStr();
    }

    return ss.GetHash();
}

bool TransactionSignatureChecker::CheckContract(const std::vector<unsigned char>& vchContractHash, std::vector<unsigned char>& vchContractAddress) const
{
    // std::cout << "TransactionSignatureChecker::CheckContract in "<< std::endl;
    vchContractAddress.clear();
    if (vchContractHash.size() != 32) {
        std::cout << "CheckContract vchContractHash.size() error: " << vchContractHash.size() << std::endl;
        return false;
    }
    if (txTo->GetSubType() != BUSINESSTYPE_CONTRACTRESULT) {
        //return false;
        UniValue attach(UniValue::VOBJ);
        CAttachInfo mainattach;
        if (mainattach.read(txTo->strAttach) && !mainattach.isNull())
        {
            attach = mainattach.getTypeObj(CAttachInfo::ATTACH_CONTRACT);
        }
        else
        {
            return false;
        }
        const UniValue& addrs = find_value(attach, "contractaddr");
        if (addrs.isNull())
            return false;
        std::string key;

        if (this->nInType == EnumTx::TX_TOKEN)
        {
            key = std::to_string(nIn);
        }
        else if (this->nInType == EnumTx::TX_GAS)
        {
            key = std::string("token") + std::to_string(nIn);
        }
        else
        {
            return false;
        }

        const UniValue& addr = find_value(addrs, key);
        if (addr.isNull())
            return false;
        CContractAddress contractAddress;
        contractAddress.SetString(addr.get_str());
        if (!contractAddress.IsValid())
            return false;

        vchContractAddress = contractAddress.GetData();
        return true;
    }

    try
	{
        UniValue attach(UniValue::VOBJ);
        CAttachInfo mainattach;
        if (mainattach.read(txTo->strAttach) && !mainattach.isNull())
        {
            attach = mainattach.getTypeObj(CAttachInfo::ATTACH_CONTRACT);
        }
        else
        {
            if (!attach.read(txTo->strAttach)) {
                std::cout << "CheckContract Invalid data object "<< std::endl;
                throw std::runtime_error("Invalid data object");
            }
            if (attach.exists("version")) {
                int version = attach["version"].get_int();
                if ( version == 2) {
                    attach = attach["list"][0];
                }
            }
        }

        const UniValue& call = find_value(attach, "call");
        const UniValue& contract = find_value(call, "contract");
        const UniValue& request = find_value(call, "request");

        //------------------------------------------------------
        // check contract hash
        uint256 hash256 = GetContractHash(call);
        // std::cout << "couttest CheckContract hash256: " << HexStr(hash256.begin(), hash256.end()).c_str() << std::endl;
        if (memcmp(hash256.begin(), &vchContractHash[0], 32) != 0) {
            std::cout << "CheckContract contract hash mismatching"<< std::endl;
            return false;
        }

        CContractAddress contractAddress;
        //------------------------------------------------------
        // check contract content
        if (!contract.isNull()) 
        {
            int nContractType = find_value(contract, "contractType").get_int();
            std::string strPubKey = find_value(contract, "pubKey").get_str();
            std::string strCode = find_value(contract, "code").get_str();
            std::vector<unsigned char> vecCode = VM::DecodeContractCode(strCode);
            std::string strSourceType = find_value(contract, "sourceType").get_str();
            std::string strAddrSign = find_value(contract, "addressSign").get_str();

            // make contract address
            bool fRealName = false;
            CKeyID realKeyId;
            realKeyId.SetHex(strPubKey);
            if (GetCaMempool()->IsValidAddress(realKeyId))
                fRealName = true;
            CKeyID keyID;
            if (fRealName)
                keyID = realKeyId;
            else
            {
                CPubKey pubKey = CPubKey(ParseHex(strPubKey));
                keyID = pubKey.GetID();
            }
            CContractCodeID contractID = CContractCodeID(Hash160(vecCode.begin(), vecCode.end()));

            std::vector<unsigned char> vchVersion = { (unsigned char) nContractType };
            contractAddress = CContractAddress(vchVersion, keyID, contractID);
            if (!contractAddress.IsValid()) {
                std::cout << "CheckContract invalid contractAddress"<< std::endl;
                return false;
            }

            vchContractAddress = contractAddress.GetData();
        }
        else
        {
            CContractAddress contractAddress(request["contractAddress"].get_str());
            if (!contractAddress.IsValid()) {
                std::cout << "CheckContract invalid contractAddress"<< std::endl;
                return false;
            }
            vchContractAddress = contractAddress.GetData();
        }

        // check request params
        // ...
        std::string strFeeBackAddr = find_value(request, "feeBackAddr").get_str();
    }
    catch (const UniValue& error)
    {
        std::cout << "CheckContract UniValue::execption: " << error.write() << std::endl;
        return false;
    }
    catch (const std::exception ex) {
        std::cout << "CheckContract std::execption: " << ex.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "CheckContract ..." << std::endl;
        return false;
    }

    // std::cout << "TransactionSignatureChecker::CheckContract end "<< std::endl;

    return true;
}

size_t static WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness, int flags)
{
    if (witversion == 0) {
        if (witprogram.size() == 20)
            return 1;

        if (witprogram.size() == 32 && witness.stack.size() > 0) {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            return subscript.GetSigOpCount(true);
        }
    }

    // Future flags may be implemented here.
    return 0;
}

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
    static const CScriptWitness witnessEmpty;

    if ((flags & SCRIPT_VERIFY_WITNESS) == 0) {
        return 0;
    }
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }

    if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()) {
        CScript::const_iterator pc = scriptSig.begin();
        vector<unsigned char> data;
        while (pc < scriptSig.end()) {
            opcodetype opcode;
            scriptSig.GetOp(pc, opcode, data);
        }
        CScript subscript(data.begin(), data.end());
        if (subscript.IsWitnessProgram(witnessversion, witnessprogram)) {
            return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
        }
    }

    return 0;
}
