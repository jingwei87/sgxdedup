#include "mbusafecrt.h"
#include "pow_enclave_t.h"
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdlib.h"
#include "string.h"
#include "systemSettings.hpp"
#include <sgx_tae_service.h>
#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>
#include <sgx_utils.h>
#include <stdio.h>
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

sgx_ra_key_128_t powSessionKey;
sgx_status_t ecall_setSessionKey(sgx_ra_context_t* ctx, sgx_ra_key_type_t type)
{
    sgx_status_t ret_status;
    ret_status = sgx_ra_get_keys(*ctx, type, &powSessionKey);
    return ret_status;
}

/*
 * work load pow_enclave
 * */
sgx_status_t ecall_calcmac(uint8_t* src, uint32_t srcLen, uint8_t* cmac, uint8_t* chunkHashList)
{
    sgx_sha256_hash_t chunkHash;
    sgx_cmac_state_handle_t cmac_ctx;
    sgx_status_t ret_status;

    sgx_cmac128_init(&powSessionKey, &cmac_ctx);
    uint32_t it, sz = 0, index = 0;
    for (it = 0; it < srcLen; it = it + sz) {
        if (srcLen - sizeof(int) < it) {
            memset(cmac, 0, 16);
            return SGX_ERROR_UNEXPECTED;
        }
        memcpy(&sz, &src[it], sizeof(int));
        it = it + 4;
        if (srcLen - it < sz) {
            memset(cmac, 0, 16);
            return SGX_ERROR_UNEXPECTED;
        }
        ret_status = sgx_sha256_msg(&src[it], sz, &chunkHash);
        if (ret_status != SGX_SUCCESS) {
            return ret_status;
        }
        sgx_cmac128_update((uint8_t*)&chunkHash, 32, cmac_ctx);
        memcpy(chunkHashList + index * 32, chunkHash, 32);
        index++;
    }

    sgx_cmac128_final(cmac_ctx, (sgx_cmac_128bit_tag_t*)cmac);
    sgx_cmac128_close(cmac_ctx);
    return SGX_SUCCESS;
}

sgx_status_t ecall_getCurrentSessionKey(char* currentSessionKeyResult)
{
    memcpy(currentSessionKeyResult, powSessionKey, 16);
    return SGX_SUCCESS;
}

sgx_status_t enclave_sealed_init(uint8_t* sealed_buf)
{
    uint32_t sgxCalSealedLen = sgx_calc_sealed_data_size(0, sizeof(sgx_ra_key_128_t));
    if (sealed_buf == NULL || sgx_is_outside_enclave(sealed_buf, sgxCalSealedLen)) {
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : input sealed_buf error.\n", 38, 1);
#endif
        return SGX_ERROR_UNEXPECTED;
    }
    uint32_t plain_text_length = 0;
    uint8_t* sealed_data = (uint8_t*)malloc(sgxCalSealedLen);
    if (sealed_data == NULL || sgx_is_outside_enclave(sealed_data, sgxCalSealedLen)) {
        free(sealed_data);
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : sealed_data buffer error.\n", 40, 1);
#endif
        return SGX_ERROR_UNEXPECTED;
    }
    memcpy_s(sealed_data, sgxCalSealedLen, sealed_buf, sgxCalSealedLen);
    uint32_t decryptSize = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
    if (decryptSize != sizeof(sgx_ra_key_128_t)) {
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : unseal decrypt size size error", 44, 1);
#endif
        free(sealed_data);
        return SGX_ERROR_UNEXPECTED;
    }
    uint8_t* unsealed_data = (uint8_t*)malloc(decryptSize);
    uint32_t unsealed_data_length = decryptSize;
    sgx_status_t ret;
    ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, &plain_text_length, unsealed_data, &unsealed_data_length);
    if (ret != SGX_SUCCESS) {
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : unseal session key error", 38, 1);
#endif
        free(sealed_data);
        free(unsealed_data);
        return SGX_ERROR_UNEXPECTED;
    } else {
        if (unsealed_data_length != decryptSize) {
#if SYSTEM_DEBUG_FLAG == 1
            char* output = (char*)malloc(256);
            snprintf(output, 256, "PowEnclave : unseal data size = %u not equal to decrypt size = %u, error\n", unsealed_data_length, decryptSize);
            print(output, 82, 1);
            free(output);
#endif
            return SGX_ERROR_UNEXPECTED;
        } else {
            memcpy_s((uint8_t*)&powSessionKey, 16 * sizeof(uint8_t), unsealed_data, 16 * sizeof(uint8_t));
            return SGX_SUCCESS;
        }
    }
}

sgx_status_t enclave_sealed_close(uint8_t* sealed_buf)
{
    char* output = (char*)malloc(256);
    uint32_t sealed_len = sizeof(sgx_sealed_data_t) + sizeof(sgx_ra_key_128_t);
    uint32_t sgxCalSealedLen = sgx_calc_sealed_data_size(0, sizeof(sgx_ra_key_128_t));
    if (sgxCalSealedLen != sealed_len) {
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : sealed length error.\n", 35, 1);
#endif
        free(output);
        return SGX_ERROR_UNEXPECTED;
    }
    // Check the sealed_buf length and check the outside pointers deeply
    if (!sealed_buf) {
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : sealed buffer error.\n", 35, 1);
#endif
        free(output);
        return SGX_ERROR_UNEXPECTED;
    }
    uint8_t* target_data = (uint8_t*)malloc(sizeof(sgx_ra_key_128_t));
    uint8_t* temp_sealed_buf = (uint8_t*)malloc(sgxCalSealedLen * sizeof(uint8_t));
    if (temp_sealed_buf == NULL || sgx_is_outside_enclave(temp_sealed_buf, sgxCalSealedLen)) {
        free(output);
        free(temp_sealed_buf);
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : sealing buffer error.\n", 36, 1);
#endif
        return SGX_ERROR_UNEXPECTED;
    }
    memset_s(temp_sealed_buf, sgxCalSealedLen, 0, sgxCalSealedLen);
    memcpy_s(target_data, 16 * sizeof(uint8_t), (uint8_t*)&powSessionKey, 16 * sizeof(uint8_t));
    sgx_status_t ret = sgx_seal_data(0, NULL, sizeof(sgx_ra_key_128_t), target_data, sgxCalSealedLen, (sgx_sealed_data_t*)temp_sealed_buf);
    free(target_data);
    if (ret != SGX_SUCCESS) {
        free(temp_sealed_buf);
        free(output);
#if SYSTEM_DEBUG_FLAG == 1
        print("PowEnclave : seal session key error.\n", 38, 1);
#endif
        return SGX_ERROR_UNEXPECTED;
    } else {
        // Backup the sealed data to outside bufferret
        memcpy_s(sealed_buf, sgxCalSealedLen, temp_sealed_buf, sgxCalSealedLen);
        return SGX_SUCCESS;
        // uint32_t decryptSize = sgx_get_encrypt_txt_len(temp_sealed_buf);
        // uint8_t* unsealed_data = (uint8_t*)malloc(decryptSize);
        // snprintf(output, 256, "unseal data size = %u\n", decryptSize);
        // print(output, 27, 2);
        // if (sgx_is_outside_enclave(unsealed_data, decryptSize)) {
        //     print("ocall close : unseal data space error\n", 39, 1);
        //     free(temp_sealed_buf);
        //     free(unsealed_data);
        //     free(output);
        //     return 5;
        // }
        // uint32_t unsealed_data_length = decryptSize;
        // uint32_t plain_text_length = 0;
        // ret = sgx_unseal_data((sgx_sealed_data_t*)temp_sealed_buf, NULL, &plain_text_length, unsealed_data, &unsealed_data_length);
        // if (ret != SGX_SUCCESS) {
        //     print("ocall close : unseal error\n", 28, 1);
        //     free(temp_sealed_buf);
        //     free(unsealed_data);
        //     free(output);
        //     return ret;
        // } else {
        //     if (unsealed_data_length != decryptSize) {
        //         snprintf(output, 256, "unseal data size = %u, decrypt size = %u\n", unsealed_data_length, decryptSize);
        //         print(output, 46, 1);
        //         free(temp_sealed_buf);
        //         free(unsealed_data);
        //         free(output);
        //         return 7;
        //     } else {
        //         print("Unsealed key = ", 16, 1);
        //         print(unsealed_data, 16, 2);
        //         free(temp_sealed_buf);
        //         free(unsealed_data);
        //         free(output);
        //         return 0;
        //     }
        // }
    }
}
