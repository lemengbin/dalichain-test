srcdir=.

LOCAL_INCLUDE = -I$(srcdir)

# src
CA_OBJ = ca/ca.o \
         ca/camempool.o

COMPRESS_INCLUDE = -I$(srcdir)/compress/include
COMPRESS_OBJ = compress/CompressAlgorithmBase.o \
               compress/LZ4Compress.o \
               compress/SnappyCompress.o \
               compress/ZLIBCompress.o

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

SUPPORT_OBJ = support/cleanse.o \
              support/lockedpool.o

# dependence
depsdir = $(srcdir)/deps

BOOST_LIB = -lboost_system -lboost_filesystem

CURL_INCLUDE = -I$(depsdir)/curl/include
CURL_LDFLAG = -L$(depsdir)/curl/lib
CURL_LIB = -lcurl

OPENSSL_INCLUDE = -I$(depsdir)/openssl/include
OPENSSL_LDFLAG = -L$(depsdir)/openssl/lib
OPENSSL_LIB = -lssl -lcrypto

SECP256K1_INCLUDE = -I$(depsdir)/secp256k1/include
SECP256K1_LDFLAG = -L$(depsdir)/secp256k1/lib
SECP256K1_LIB = -lsecp256k1

UNIVALUE_INCLUDE = -I$(depsdir)/univalue/include
UNIVALUE_LDFLAG = -L$(depsdir)/univalue/lib
UNIVALUE_LIB = -lunivalue

LZ4_INCLUDE = -I$(depsdir)/lz4/include
LZ4_LDFLAG = -L$(depsdir)/lz4/lib
LZ4_LIB = -llz4

SNAPPY_INCLUDE = -I$(depsdir)/snappy/include
SNAPPY_LDFLAG = -L$(depsdir)/snappy/lib
SNAPPY_LIB = -lsnappy

ZLIB_INCLUDE = -I$(depsdir)/zlib/include
ZLIB_LDFLAG = -L$(depsdir)/zlib/lib
ZLIB_LIB = -lz

# all
INCLUDES = $(LOCAL_INCLUDE) \
           $(COMPRESS_INCLUDE) \
           $(IPFS_INCLUDE) \
           $(CURL_INCLUDE) \
           $(OPENSSL_INCLUDE) \
           $(SECP256K1_INCLUDE) \
           $(UNIVALUE_INCLUDE) \
           $(LZ4_INCLUDE) \
           $(SNAPPY_INCLUDE) \
           $(ZLIB_INCLUDE)

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
       $(SUPPORT_OBJ)

LIBS = $(SECP256K1_LIB) \
       $(BOOST_LIB) \
       $(LZ4_LIB) \
       $(SNAPPY_LIB) \
       $(ZLIB_LIB) \
       $(CURL_LIB) \
       $(OPENSSL_LIB) \
       $(UNIVALUE_LIB) \
       -pthread -ldl

LDFLAGS = $(SECP256K1_LDFLAG) \
          $(LZ4_LDFLAG) \
          $(SNAPPY_LDFLAG) \
          $(ZLIB_LDFLAG) \
          $(CURL_LDFLAG) \
          $(OPENSSL_LDFLAG) \
          $(UNIVALUE_LDFLAG)

CXX = g++
CXXFLAGS = -static -DHAVE_CONFIG_H -std=c++11

tx_constructor: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS) $(LIBS)

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
	rm tx_constructor -rf
