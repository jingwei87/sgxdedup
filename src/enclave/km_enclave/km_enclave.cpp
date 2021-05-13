#include "km_enclave_t.h"
#include "mbusafecrt.h"
#include "systemSettings.hpp"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <sgx_tae_service.h>
#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>
#include <sgx_utils.h>
#include <unordered_map>

using namespace std;

#define MAX_SPECULATIVE_KEY_SIZE 80 * 1024 * 1024
#define MAX_SPECULATIVE_CLIENT_NUMBER 1
#define MAX_SPECULATIVE_KEY_SIZE_PER_CLIENT MAX_SPECULATIVE_KEY_SIZE / MAX_SPECULATIVE_CLIENT_NUMBER

// static const sgx_ec256_public_t def_service_public_key = {
//     { 0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
//         0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
//         0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
//         0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38 },
//     { 0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
//         0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
//         0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
//         0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06 }

// }; //little endding/hard coding

#define PSE_RETRIES 5 /* Arbitrary. Not too long, not too short. */
/*
 * quote pow_enclave
 * */

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
    sgx_ra_context_t* ctx, sgx_status_t* pse_status)
{
    sgx_status_t ra_status;

    /*
   * If we want platform services, we must create a PSE session
   * before calling sgx_ra_init()
   */

    if (b_pse) {
        int retries = PSE_RETRIES;
        do {
            *pse_status = sgx_create_pse_session();
            if (*pse_status != SGX_SUCCESS)
                return SGX_ERROR_UNEXPECTED;
        } while (*pse_status == SGX_ERROR_BUSY && retries--);
        if (*pse_status != SGX_SUCCESS)
            return SGX_ERROR_UNEXPECTED;
    }

    ra_status = sgx_ra_init(&key, b_pse, ctx);

    if (b_pse) {
        int retries = PSE_RETRIES;
        do {
            *pse_status = sgx_create_pse_session();
            if (*pse_status != SGX_SUCCESS)
                return SGX_ERROR_UNEXPECTED;
        } while (*pse_status == SGX_ERROR_BUSY && retries--);
        if (*pse_status != SGX_SUCCESS)
            return SGX_ERROR_UNEXPECTED;
    }

    return ra_status;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
    sgx_status_t ret;
    ret = sgx_ra_close(ctx);
    return ret;
}

int encrypt(uint8_t* plaint, uint32_t plaintLen, uint8_t* symKey,
    uint32_t symKeyLen, uint8_t* cipher, uint32_t* cipherLen);

int decrypt(uint8_t* cipher, uint32_t cipherLen, uint8_t* symKey,
    uint32_t symKeyLen, uint8_t* plaint, uint32_t* plaintLen);

sgx_ra_key_128_t sessionkey;
sgx_ra_key_128_t macKey;
uint8_t currentSessionKey_[32];
uint8_t serverSecret_[32];
uint32_t keyRegressionMaxTimes_;
uint32_t keyRegressionCurrentTimes_;
uint8_t* nextEncryptionMaskSet_;
typedef struct {
    uint32_t keyGenerateCounter = 0;
    uint32_t currentKeyGenerateCounter = 0;
    uint32_t maskOffset = 0;
    int offlineFlag = -1; // -1 -> no offline; 1 -> offline
    uint8_t nonce[16 - sizeof(uint32_t)];
} ClientInfo_t;
std::unordered_map<int, ClientInfo_t> clientList_;

sgx_status_t ecall_enclave_close()
{
    clientList_.clear();
    free(nextEncryptionMaskSet_);
    return SGX_SUCCESS;
}

sgx_status_t ecall_setServerSecret(uint8_t* keyd, uint32_t keydLen)
{
    uint8_t* secretTemp = (uint8_t*)malloc(128 + keydLen);
    memset(secretTemp, 1, keydLen + 128);
    memcpy_s(secretTemp + 128, 256, keyd, keydLen);
    sgx_status_t sha256Status = sgx_sha256_msg(secretTemp, 128 + keydLen, (sgx_sha256_hash_t*)serverSecret_);
    free(secretTemp);
    return sha256Status;
}

sgx_status_t ecall_getServerSecret(uint8_t* secret)
{
    memcpy_s(secret, 32, serverSecret_, 32);
    return SGX_SUCCESS;
}

sgx_status_t ecall_setKeyRegressionCounter(uint32_t keyRegressionMaxTimes)
{
    keyRegressionMaxTimes_ = keyRegressionMaxTimes;
    keyRegressionCurrentTimes_ = keyRegressionMaxTimes_;
    clientList_.clear();
    return SGX_SUCCESS;
}

sgx_status_t ecall_clientStatusModify(int clientID, uint8_t* inputBuffer, uint8_t* hmacBuffer)
{
    auto it = clientList_.begin();
    while (it != clientList_.end()) {
        it->second.keyGenerateCounter += it->second.currentKeyGenerateCounter;
        it->second.currentKeyGenerateCounter = 0;
        it++;
    }
    uint8_t hmac[32];
    sgx_hmac_sha256_msg(inputBuffer, 16, currentSessionKey_, 32, hmac, 32);
    uint8_t plaintextBuffer[16];
    uint32_t recvedCounter = 0, plaintextLen;
    decrypt(inputBuffer, 16, currentSessionKey_, 32, plaintextBuffer, &plaintextLen);
    if (memcmp(hmac, hmacBuffer, 32) != 0) {
        return SGX_ERROR_INVALID_SIGNATURE; // hmac not right , reject
    } else {
        memcpy_s(&recvedCounter, sizeof(uint32_t), plaintextBuffer, sizeof(uint32_t));
#if SYSTEM_DEBUG_FLAG == 1
        print("KeyEnclave : client Info = ", 28, 1);
        print((char*)plaintextBuffer, sizeof(uint32_t), 2);
        print((char*)plaintextBuffer + sizeof(uint32_t), 12, 2);
#endif
        if (clientList_.find(clientID) == clientList_.end()) {
#if SYSTEM_DEBUG_FLAG == 1
            print("KeyEnclave : not found client info", 35, 1);
#endif
            ClientInfo_t newClient;
            memcpy_s(newClient.nonce, 12, plaintextBuffer + sizeof(uint32_t), 12);
            newClient.keyGenerateCounter = 0;
            newClient.currentKeyGenerateCounter = 0;
            auto index = clientList_.begin();
            while (index != clientList_.end()) {
                if (memcmp(index->second.nonce, newClient.nonce, 12) == 0) {
                    return SGX_ERROR_INVALID_PARAMETER;
                }
                index++;
            }
#if SYSTEM_DEBUG_FLAG == 1
            print("KeyEnclave : start insert new clint info", 41, 1);
#endif
            clientList_.insert(make_pair(clientID, newClient));
#if SYSTEM_DEBUG_FLAG == 1
            print("KeyEnclave : insert new client info done", 41, 1);
#endif
            if (recvedCounter == 0) {
                return SGX_SUCCESS; // success, first login
            } else {
                return SGX_ERROR_UNEXPECTED; // key enclave no information, send reset to client
            }
        } else {
#if SYSTEM_DEBUG_FLAG == 1
            print("KeyEnclave : found client info", 31, 1);
#endif
            if (clientList_.at(clientID).keyGenerateCounter == recvedCounter) {
                return SGX_SUCCESS; // success, use offline mode
            } else {
                memcpy_s(clientList_.at(clientID).nonce, 12, plaintextBuffer + sizeof(uint32_t), 12);
                clientList_.at(clientID).keyGenerateCounter = 0;
                clientList_.at(clientID).currentKeyGenerateCounter = 0;
                clientList_.at(clientID).offlineFlag = -1;
                return SGX_ERROR_UNEXPECTED; // key enclave information error, send reset to client
            }
        }
    }
}

sgx_status_t ecall_setSessionKey(sgx_ra_context_t* ctx)
{
    sgx_status_t ret_status;
    ret_status = sgx_ra_get_keys(*ctx, SGX_RA_KEY_SK, &sessionkey);
    if (ret_status != SGX_SUCCESS) {
        return ret_status;
    } else {
        ret_status = sgx_ra_get_keys(*ctx, SGX_RA_KEY_MK, &macKey);
        if (ret_status != SGX_SUCCESS) {
            return ret_status;
        } else {
            return SGX_SUCCESS;
        }
    }
}

sgx_status_t ecall_setNextEncryptionMask()
{
    EVP_CIPHER_CTX* cipherctx_ = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
    unsigned char currentKeyBase[32];
    unsigned char currentKey[32];
    int cipherlen, len;
    int generatedNumber = 0;
#if SYSTEM_DEBUG_FLAG == 1
    print("Key enclave generate mask total number", 39, 1);
    int number = clientList_.size();
    print((char*)&number, 4, 3);
#endif
    auto it = clientList_.begin();
    while (it != clientList_.end() && generatedNumber < MAX_SPECULATIVE_CLIENT_NUMBER) {
#if SYSTEM_DEBUG_FLAG == 1
        print((char*)&generatedNumber, 4, 3);
        print("Key enclave generate mask for client start", 43, 1);
        print((char*)it->second.nonce, 32, 2);
#endif
        uint32_t currentCounter = it->second.keyGenerateCounter + it->second.currentKeyGenerateCounter;
        it->second.offlineFlag = -1;
        uint8_t nonce[12];
        memcpy_s(nonce, 12, it->second.nonce, 12);
        uint32_t offset = 0;
        for (int j = 0; j < generatedNumber; j++) {
            offset += MAX_SPECULATIVE_KEY_SIZE_PER_CLIENT;
        }
        it->second.offlineFlag = 1;
        it->second.maskOffset = offset;
        for (int i = 0; i < MAX_SPECULATIVE_KEY_SIZE_PER_CLIENT / 32; i++) {
            memcpy(currentKeyBase, &currentCounter, sizeof(uint32_t));
            memcpy(currentKeyBase + sizeof(uint32_t), nonce, 16 - sizeof(uint32_t));
            currentCounter++;
            memcpy(currentKeyBase + 16, &currentCounter, sizeof(uint32_t));
            memcpy(currentKeyBase + 16 + sizeof(uint32_t), nonce, 16 - sizeof(uint32_t));
            currentCounter++;
            if (EVP_EncryptInit_ex(cipherctx_, EVP_aes_256_ecb(), NULL, currentSessionKey_, currentSessionKey_) != 1) {
                EVP_CIPHER_CTX_cleanup(cipherctx_);
                EVP_CIPHER_CTX_free(cipherctx_);
                return SGX_ERROR_UNEXPECTED;
            }

            if (EVP_EncryptUpdate(cipherctx_, currentKey, &cipherlen, currentKeyBase, 32) != 1) {
                EVP_CIPHER_CTX_cleanup(cipherctx_);
                EVP_CIPHER_CTX_free(cipherctx_);
                return SGX_ERROR_UNEXPECTED;
            }

            if (EVP_EncryptFinal_ex(cipherctx_, currentKey + cipherlen, &len) != 1) {
                EVP_CIPHER_CTX_cleanup(cipherctx_);
                EVP_CIPHER_CTX_free(cipherctx_);
                return SGX_ERROR_UNEXPECTED;
            }
#if SYSTEM_DEBUG_FLAG == 1
            uint32_t max = MAX_SPECULATIVE_KEY_SIZE_PER_CLIENT;
            print((char*)&offset, 4, 3);
            print((char*)&generatedNumber, 4, 3);
            print((char*)&i, 4, 3);
            print((char*)&max, 4, 3);
#endif
            memcpy_s(nextEncryptionMaskSet_ + offset + i * 32, MAX_SPECULATIVE_KEY_SIZE - offset - i * 32, currentKey, 32);
        }
        it++;
        generatedNumber++;
#if SYSTEM_DEBUG_FLAG == 1
        print("Key enclave generate mask for client done", 41, 1);
#endif
    }
    EVP_CIPHER_CTX_cleanup(cipherctx_);
    EVP_CIPHER_CTX_free(cipherctx_);
    return SGX_SUCCESS;
}

sgx_status_t ecall_setSessionKeyUpdate()
{
    memset(currentSessionKey_, 0, 32);
    uint8_t hashDataTemp[32];
    uint8_t hashResultTemp[32];
    memcpy_s(hashDataTemp, sizeof(sgx_ra_key_128_t), sessionkey, sizeof(sgx_ra_key_128_t));
    memcpy_s(hashDataTemp + sizeof(sgx_ra_key_128_t), sizeof(sgx_ra_key_128_t), macKey, sizeof(sgx_ra_key_128_t));
    for (int i = 0; i < keyRegressionCurrentTimes_; i++) {
        sgx_status_t sha256Status = sgx_sha256_msg(hashDataTemp, 32, (sgx_sha256_hash_t*)hashResultTemp);
        if (sha256Status != SGX_SUCCESS) {
            return sha256Status;
        }
        memcpy_s(hashDataTemp, 32, hashResultTemp, 32);
    }
    uint8_t finalHashBuffer[40];
    memset(finalHashBuffer, 0, 40);
    memcpy(finalHashBuffer + 8, hashDataTemp, 32);
    sgx_status_t sha256Status = sgx_sha256_msg(finalHashBuffer, 40, (sgx_sha256_hash_t*)hashResultTemp);
    if (sha256Status != SGX_SUCCESS) {
        return sha256Status;
    }
    memcpy_s(currentSessionKey_, 32, hashResultTemp, 32);
    keyRegressionCurrentTimes_--;
    return SGX_SUCCESS;
}

sgx_status_t ecall_getCurrentSessionKey(char* currentSessionKeyResult)
{
    memcpy(currentSessionKeyResult, currentSessionKey_, 32);
    memcpy(currentSessionKeyResult + 32, sessionkey, 16);
    memcpy(currentSessionKeyResult + 48, macKey, 16);
    return SGX_SUCCESS;
}

sgx_status_t ecall_setCTRMode()
{
    nextEncryptionMaskSet_ = (uint8_t*)malloc(MAX_SPECULATIVE_KEY_SIZE * sizeof(uint8_t));
    if (nextEncryptionMaskSet_ == NULL) {
        return SGX_ERROR_UNEXPECTED;
    } else {
        memset(nextEncryptionMaskSet_, 0, MAX_SPECULATIVE_KEY_SIZE);
    }
    return SGX_SUCCESS;
}

sgx_status_t ecall_keygen_ctr(uint8_t* src, uint32_t srcLen, uint8_t* key, int clientID)
{
    uint8_t hmac[32];
    int originalHashLen = srcLen - 32;
    sgx_hmac_sha256_msg(src, originalHashLen, currentSessionKey_, 32, hmac, 32);
    if (memcmp(hmac, src + originalHashLen, 32) != 0) {
        return SGX_ERROR_INVALID_SIGNATURE; // hmac not right , reject
    }
    uint8_t hash[32], originhash[originalHashLen], keySeed[originalHashLen], hashTemp[64], mask[originalHashLen * 2];
    uint32_t currentCounter = clientList_.at(clientID).currentKeyGenerateCounter;
    uint32_t previousCounter = clientList_.at(clientID).keyGenerateCounter;
    uint32_t maskBufferOffset = clientList_.at(clientID).maskOffset;
    if ((16 * (currentCounter + (originalHashLen / 32) * 4)) < MAX_SPECULATIVE_KEY_SIZE_PER_CLIENT && clientList_.at(clientID).offlineFlag == 1) {
        for (int i = 0; i < originalHashLen; i++) {
            originhash[i] = src[i] ^ nextEncryptionMaskSet_[maskBufferOffset + currentCounter * 16 + i];
        }
    } else {
        EVP_CIPHER_CTX* cipherctx_ = EVP_CIPHER_CTX_new();
        if (cipherctx_ == NULL) {
            return SGX_ERROR_UNEXPECTED;
        }
        unsigned char currentKeyBase[32];
        unsigned char currentKey[32];
        unsigned char nonce[12];
        memcpy_s(nonce, 12, clientList_.at(clientID).nonce, 12);
        int cipherlen, len;
        EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
        uint32_t currentCounterTemp = previousCounter + currentCounter;
        for (int i = 0; i < originalHashLen * 2 / 32; i++) {
            memcpy_s(currentKeyBase, 32, &currentCounterTemp, sizeof(uint32_t));
            memcpy_s(currentKeyBase + sizeof(uint32_t), 32, nonce, 16 - sizeof(uint32_t));
            currentCounterTemp++;
            memcpy_s(currentKeyBase + 16, 32, &currentCounterTemp, sizeof(uint32_t));
            memcpy_s(currentKeyBase + 16 + sizeof(uint32_t), 32, nonce, 16 - sizeof(uint32_t));
            currentCounterTemp++;
            if (!EVP_EncryptInit_ex(cipherctx_, EVP_aes_256_ecb(), NULL, currentSessionKey_, currentSessionKey_)) {
                EVP_CIPHER_CTX_cleanup(cipherctx_);
                EVP_CIPHER_CTX_free(cipherctx_);
                return SGX_ERROR_UNEXPECTED;
            }
            if (EVP_EncryptUpdate(cipherctx_, currentKey, &cipherlen, currentKeyBase, 32) != 1) {
                EVP_CIPHER_CTX_cleanup(cipherctx_);
                EVP_CIPHER_CTX_free(cipherctx_);
                return SGX_ERROR_UNEXPECTED;
            }
            if (EVP_EncryptFinal_ex(cipherctx_, currentKey + cipherlen, &len) != 1) {
                EVP_CIPHER_CTX_cleanup(cipherctx_);
                EVP_CIPHER_CTX_free(cipherctx_);
                return SGX_ERROR_UNEXPECTED;
            }
            memcpy_s(mask + i * 32, originalHashLen * 2 - i * 32, currentKey, 32);
        }
        EVP_CIPHER_CTX_cleanup(cipherctx_);
        EVP_CIPHER_CTX_free(cipherctx_);
        for (int i = 0; i < originalHashLen; i++) {
            originhash[i] = src[i] ^ mask[i];
        }
    }
    for (uint32_t index = 0; index < (originalHashLen / 32); index++) {
        memcpy_s(hashTemp, 64, originhash + index * 32, 32);
        memcpy_s(hashTemp + 32, 64, serverSecret_, 32);
        sgx_status_t sha256Status = sgx_sha256_msg(hashTemp, 64, (sgx_sha256_hash_t*)hash);
        if (sha256Status != SGX_SUCCESS) {
            return sha256Status;
        }
        memcpy_s(keySeed + index * 32, originalHashLen - index * 32, hash, 32);
#if SYSTEM_DEBUG_FLAG == 1
        // print("KeyEnclave : Chunk Key = ", 25, 1);
        // print((char*)hash, 32, 2);
#endif
    }
    if ((currentCounter * 16 + originalHashLen) < MAX_SPECULATIVE_KEY_SIZE_PER_CLIENT && clientList_.at(clientID).offlineFlag == 1) {
        for (int i = 0; i < originalHashLen; i++) {
            key[i] = keySeed[i] ^ nextEncryptionMaskSet_[maskBufferOffset + currentCounter * 16 + originalHashLen + i];
        }
    } else {
        for (int i = 0; i < originalHashLen; i++) {
            key[i] = keySeed[i] ^ mask[i + originalHashLen];
        }
    }
    sgx_hmac_sha256_msg(key, originalHashLen, currentSessionKey_, 32, key + originalHashLen, 32);
    clientList_.at(clientID).currentKeyGenerateCounter += (originalHashLen * 2 / 16);
    return SGX_SUCCESS;
}

sgx_status_t ecall_keygen(uint8_t* src, uint32_t srcLen, uint8_t* key)
{
    uint32_t decryptLen, encryptLen;
    int originalHashLen = srcLen - 32;
    uint8_t hash[32], originhash[originalHashLen], keySeed[originalHashLen], hashTemp[64], hmac[32];
    sgx_hmac_sha256_msg(src, originalHashLen, currentSessionKey_, 32, hmac, 32);
    if (memcmp(hmac, src + originalHashLen, 32) != 0) {
#if SYSTEM_DEBUG_FLAG == 1
        print("KeyEnclave : recved hmac = ", 28, 1);
        print((char*)src + originalHashLen, 32, 2);
        print("KeyEnclave : generated hmac = ", 31, 1);
        print((char*)hmac, 32, 2);
#endif
        return SGX_ERROR_INVALID_SIGNATURE; // hmac not right , reject
    }

    if (!decrypt(src, originalHashLen, currentSessionKey_, 32, originhash, &decryptLen)) {
        return SGX_ERROR_UNEXPECTED;
    } else {
        for (uint32_t index = 0; index < (originalHashLen / 32); index++) {
            memcpy_s(hashTemp, 64, originhash + index * 32, 32);
            memcpy_s(hashTemp + 32, 64, serverSecret_, 32);
            sgx_status_t sha256Status = sgx_sha256_msg(hashTemp, 64, (sgx_sha256_hash_t*)hash);
            if (sha256Status != SGX_SUCCESS) {
                return sha256Status;
            } else {
                memcpy_s(keySeed + index * 32, originalHashLen - index * 32, hash, 32);
            }
        }
        if (!encrypt(keySeed, originalHashLen, currentSessionKey_, 32, key, &encryptLen)) {
            return SGX_ERROR_UNEXPECTED;
        } else {
            sgx_hmac_sha256_msg(key, originalHashLen, currentSessionKey_, 32, key + originalHashLen, 32);
            return SGX_SUCCESS;
        }
    }
}

int encrypt(uint8_t* plaint, uint32_t plaintLen, uint8_t* symKey,
    uint32_t symKeyLen, uint8_t* cipher, uint32_t* cipherLen)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, symKey, symKey)) {
        goto error;
    }

    if (!EVP_EncryptUpdate(ctx, cipher, (int*)cipherLen, plaint, plaintLen)) {
        goto error;
    }

    int len;
    if (!EVP_EncryptFinal_ex(ctx, cipher + *cipherLen, &len)) {
        goto error;
    }
    cipherLen += len;
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
error:
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt(uint8_t* cipher, uint32_t cipherLen, uint8_t* symKey,
    uint32_t symKeyLen, uint8_t* plaint, uint32_t* plaintLen)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, symKey, symKey)) {
        goto error;
    }

    if (!EVP_DecryptUpdate(ctx, plaint, (int*)plaintLen, cipher, cipherLen)) {
        goto error;
    }

    int decryptLen;
    if (!EVP_DecryptFinal_ex(ctx, plaint + *plaintLen, &decryptLen)) {
        goto error;
    }
    plaintLen += decryptLen;

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 1;

error:
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}