#ifndef CONSTRUCT_TX_H
#define CONSTRUCT_TX_H

#include <string>
#include "univalue.h"
#include "transaction.h"

UniValue ParseJsonFile(const std::string& strFile);

bool CreateTransaction(const std::string& strCommand, const std::string& strFile, int hSocket);

bool CreateCommonTx(std::string& strRawTx, const UniValue& params);
bool CreatePublishTx(std::string& strRawTx, const UniValue& params);
bool CreateExchangeTx(std::string& strRawTx, const UniValue& params);
bool CreateMultiSigTx(std::string& strRawTx, const UniValue& params);
bool CreateContractTx(std::string& strRawTx, const UniValue& params);

bool BuildTx(CMutableTransaction& mtx, const UniValue& params);
bool BuildTxBasicPart(CMutableTransaction& mtx, const UniValue& params);
bool BuildTxGasTokenPart(CMutableTransaction& mtx, const UniValue& params);

bool SignTx(CMutableTransaction& mtx, const UniValue& params);
bool SignTxBasicPart(CMutableTransaction& mtx, const UniValue& params);
bool SignTxGasTokenPart(CMutableTransaction& mtx, const UniValue& params);

bool SendTransaction(const std::string& strRawTx, int& hSocket, bool fWitness = false);

#endif
