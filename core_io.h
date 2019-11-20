#ifndef CORE_IO_H
#define CORE_IO_H

#include <string>

class CTransaction;

extern std::string EncodeHexTx(const CTransaction& tx, const int serialFlags = 0);

#endif
