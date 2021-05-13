#ifndef SGXDEDUP_SYSTEMSETTINGS_HPP
#define SGXDEDUP_SYSTEMSETTINGS_HPP
/* System Test Settings: 0-disable; 1-enable */
#define SYSTEM_BREAK_DOWN 0
#define SYSTEM_DEBUG_FLAG 0
#define OPENSSL_V_1_0_2 0
#define ENCLAVE_SEALED_INIT_ENABLE 1 // set to 0 means do remote attestation every startup
#define MULTI_CLIENT_UPLOAD_TEST 0 // set to 1 means not write content to disk on server side
#define TRACE_DRIVEN_TEST 1

/* Key Generation method Settings: 0-disable; 1-enable */
#define KEY_GEN_SGX_CFB 0
#define KEY_GEN_SGX_CTR 1
#define KEY_GEN_METHOD_TYPE KEY_GEN_SGX_CFB

/* System Running Type Settings */
#define CHUNKER_FIX_SIZE_TYPE 0 //macro for the type of fixed-size chunker
#define CHUNKER_VAR_SIZE_TYPE 1 //macro for the type of variable-size chunker
#define CHUNKER_TRACE_DRIVEN_TYPE_FSL 2 //macro for the type of fsl dataset chunk generator
#define CHUNKER_TRACE_DRIVEN_TYPE_UBC 3 //macro for the type of ms dataset chunk generator

/* System Infomation Size Settings */
#define CHUNK_HASH_SIZE 32
#define CHUNK_ENCRYPT_KEY_SIZE 32
#define FILE_NAME_HASH_SIZE 32
#define MAX_CHUNK_SIZE 16384 //macro for the max size of variable-size chunker
#define NETWORK_MESSAGE_DATA_SIZE 18 * 1000 * 1000
#define SGX_MESSAGE_MAX_SIZE 1024 * 1024
#define CRYPTO_BLOCK_SZIE 16
#define KEY_SERVER_SESSION_KEY_SIZE 32

/* System Infomation Type Settings */
#define DATA_TYPE_RECIPE 1
#define DATA_TYPE_CHUNK 2
#define CHUNK_TYPE_ENCRYPTED 0
#define CHUNK_TYPE_VERIFY_PASSED 1
#define CHUNK_TYPE_VERIFY_NOT_PASSED 2
#define CHUNK_TYPE_SENDING_OVER 3
#define CHUNK_TYPE_UNIQUE 4
#define CHUNK_TYPE_DUPLICATE 5
#define CHUNK_TYPE_INIT 6
#define CHUNK_TYPE_NEED_UPLOAD 7

#endif //SGXDEDUP_SYSTEMSETTINGS_HPP