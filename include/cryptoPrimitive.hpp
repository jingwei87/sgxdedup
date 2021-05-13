#ifndef SGXDEDUP_CRYPTOPRIMITIVE_HPP
#define SGXDEDUP_CRYPTOPRIMITIVE_HPP
#include "configure.hpp"
#include "dataStructure.hpp"
#include <bits/stdc++.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslconf.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pthread.h>

#define OPENSSL_THREAD_DEFINES

using namespace std;

typedef struct {
    pthread_mutex_t* lockList;
    long* cntList;
} opensslLock_t;

class CryptoPrimitive {
private:
    const EVP_MD* md_;

    int hashSize_;
    int blockSize_;

    EVP_CIPHER_CTX* cipherctx_;
    // EVP_MD_CTX* mdctx_;
    CMAC_CTX* cmacctx_;
    const EVP_CIPHER* cipher_;
    u_char* iv_;

    static opensslLock_t* opensslLock_;
    static void opensslLockingCallback_(int mode, int type, const char* file, int line);
    static void opensslThreadID_(CRYPTO_THREADID* id);

public:
    u_char* chunkKeyEncryptionKey_;

    CryptoPrimitive();
    ~CryptoPrimitive();
    static bool opensslLockSetup();
    static bool opensslLockCleanup();
    bool generateHash(u_char* dataBuffer, const int dataSize, u_char* hash);
    bool encryptWithKey(u_char* dataBuffer, const int dataSize, u_char* key, u_char* ciphertext);
    bool decryptWithKey(u_char* ciphertext, const int dataSize, u_char* key, u_char* dataBuffer);
    bool keyExchangeEncrypt(u_char* dataBuffer, const int dataSize, u_char* key, u_char* iv, u_char* ciphertext);
    bool keyExchangeDecrypt(u_char* ciphertext, const int dataSize, u_char* key, u_char* iv, u_char* dataBuffer);
    bool keyExchangeCTRBaseGenerate(u_char* nonce, uint32_t counter, uint32_t generateNumber, u_char* key, u_char* iv, u_char* ctrBaseBuffer);
    bool encryptChunk(Chunk_t& chunk);
    bool decryptChunk(Chunk_t& chunk);
    bool decryptChunk(u_char* chunkData, int chunkSize, u_char* key, u_char* plaintData);
    bool cmac128(u_char* hashList, uint32_t chunkNumber, u_char* mac, u_char* key, int keyLen);
    bool sha256Hmac(u_char* data, uint32_t dataSize, u_char* mac, u_char* key, int keyLen);
    void PRINT_BYTE_ARRAY(FILE* file, void* mem, uint32_t len)
    {
        if (!mem || !len) {
            fprintf(file, "\n( null )\n");
            return;
        }
        uint8_t* array = (uint8_t*)mem;
        fprintf(file, "%u bytes:\n{\n", len);
        uint32_t i = 0;
        for (i = 0; i < len - 1; i++) {
            fprintf(file, "0x%x, ", array[i]);
            if (i % 8 == 7)
                fprintf(file, "\n");
        }
        fprintf(file, "0x%x ", array[i]);
        fprintf(file, "\n}\n");
    }
};

#endif //SGXDEDUP_CRYPTOPRIMITIVE_HPP