srcdir=.

LOCAL_INCLUDE = -I$(srcdir)

CA_OBJ = ca/ca.o \
         ca/camempool.o

COMPRESS_INCLUDE = -I$(srcdir)/compress/include
COMPRESS_OBJ = compress/CompressAlgorithmBase.o \
               compress/LZ4Compress.o \
               compress/SnappyCompress.o \
               compress/ZLIBCompress.o

CONFIG_INCLUDE = -I$(srcdir)/config

CONSENSUS_OBJ = consensus/merkle.o

CRYPTO_OBJ = crypto/aes.o \
             crypto/hmac_sha256.o \
             crypto/hmac_sha512.o \
             crypto/ripemd160.o \
             crypto/sha1.o \
             crypto/sha256.o \
             crypto/sha512.o

IPFS_INCLUDE = -I$(srcdir)/ipfsapi/include
IPFS_OBJ = ipfsapi/src/client.o \
           ipfsapi/src/http/transport-curl.o \
           ipfsapi/src/ipfsapi.o

SCRIPT_OBJ = script/standard.o \
             script/sign.o \
             script/script.o \
             script/interpreter.o

SECP256K1_INCLUDE = -I$(srcdir)/secp256k1/include
SECP256K1_LIB = $(srcdir)/secp256k1/lib/libsecp256k1.a

SUPPORT_OBJ = support/cleanse.o \
              support/lockedpool.o

UNIVALIE_INCLUDE = -I$(srcdir)/univalue/include
UNIVALUE_OBJ = univalue/src/univalue.o \
               univalue/src/univalue_read.o \
               univalue/src/univalue_write.o

INCLUDES = $(LOCAL_INCLUDE) \
           $(COMPRESS_INCLUDE) \
           $(CONFIG_INCLUDE) \
           $(IPFS_INCLUDE) \
           $(SECP256K1_INCLUDE) \
           $(UNIVALIE_INCLUDE)
OBJS = main.o \
       amount.o \
       arith_uint256.o \
       attachinfo.o \
       base58.o \
       chainparams.o \
       core_write.o \
       GlobalProfile.o \
       hash.o \
       key.o \
       keystore.o \
       net.o \
       protocol.o \
       pubkey.o \
       random.o \
       sync.o \
       transaction.o \
       uint256.o \
       util.o \
       utilstrencodings.o \
       construct_tx.o \
       common_tx.o \
       publish_tx.o \
       exchange_tx.o \
       multisig_tx.o \
       contract_tx.o \
       $(CA_OBJ) \
       $(COMPRESS_OBJ) \
       $(CONSENSUS_OBJ) \
       $(CRYPTO_OBJ) \
       $(IPFS_OBJ) \
       $(SCRIPT_OBJ) \
       $(SUPPORT_OBJ) \
       $(UNIVALUE_OBJ)

CXX = g++
CXXFLAGS = -g -DHAVE_CONFIG_H -std=c++11
LIBS = $(SECP256K1_LIB) -lboost_thread -lboost_system -lboost_filesystem -llz4 -lsnappy -lz -lcrypto -lssl -pthread -lcurl

test: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS) $(INCLUDES)

main.o : main.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
amount.o : amount.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
arith_uint256.o : arith_uint256.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
attachinfo.o : attachinfo.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
base58.o : base58.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
chainparams.o : chainparams.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
core_write.o : core_write.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
GlobalProfile.o : GlobalProfile.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
hash.o : hash.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
key.o : key.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
keystore.o : keystore.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
net.o : net.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
protocol.o : protocol.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
pubkey.o : pubkey.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
random.o : random.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
sync.o : sync.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
transaction.o : transaction.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
uint256.o : uint256.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
util.o : util.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
utilstrencodings.o : utilstrencodings.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
construct_tx.o : construct_tx.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
common_tx.o : common_tx.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
publish_tx.o : publish_tx.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
exchange_tx.o : exchange_tx.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
multisig_tx.o : multisig_tx.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
contract_tx.o : contract_tx.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
ca/ca.o : ca/ca.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
ca/camempool.o : ca/camempool.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
compress/CompressAlgorithmBase.o : compress/CompressAlgorithmBase.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
compress/LZ4Compress.o : compress/LZ4Compress.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
compress/SnappyCompress.o : compress/SnappyCompress.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
compress/ZLIBCompress.o : compress/ZLIBCompress.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
consensus/merkle.o : consensus/merkle.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/aes.o : crypto/aes.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/hmac_sha256.o : crypto/hmac_sha256.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/hmac_sha512.o : crypto/hmac_sha512.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/ripemd160.o : crypto/ripemd160.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/sha1.o : crypto/sha1.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/sha256.o : crypto/sha256.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
crypto/sha512.o : crypto/sha512.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
ipfsapi/src/client.o : ipfsapi/src/client.cc
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
ipfsapi/src/http/transport-curl.o : ipfsapi/src/http/transport-curl.cc
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
ipfsapi/src/ipfsapi.o : ipfsapi/src/ipfsapi.cc
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
script/standard.o : script/standard.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
script/sign.o : script/sign.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
script/script.o : script/script.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
script/interpreter.o : script/interpreter.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
support/cleanse.o : support/cleanse.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
support/lockedpool.o : support/lockedpool.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
univalue/src/univalue.o : univalue/src/univalue.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
univalue/src/univalue_read.o : univalue/src/univalue_read.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)
univalue/src/univalue_write.o : univalue/src/univalue_write.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) $(INCLUDES)

clean:
	rm *.o -rf
	rm ca/*.o -rf
	rm compress/*.o -rf
	rm consensus/*.o -rf
	rm crypto/*.o -rf
	rm ipfsapi/src/*.o -rf
	rm ipfsapi/src/http/*.o -rf
	rm script/*.o -rf
	rm support/*.o -rf
	rm univalue/src/*.o -rf
	rm test -rf
