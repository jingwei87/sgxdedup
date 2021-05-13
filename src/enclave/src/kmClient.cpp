#include "kmClient.hpp"
#include "sgxErrorSupport.h"

using namespace std;
extern Configure config;

struct timeval timestartkmClient;
struct timeval timeendKmClient;

void PRINT_BYTE_ARRAY_KM(
    FILE* file, void* mem, uint32_t len)
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

void print(const char* mem, uint32_t len, uint32_t type)
{
    if (type == 1) {
        cout << mem << endl;
    } else if (type == 3) {
        uint32_t number;
        memcpy(&number, mem, sizeof(uint32_t));
        cout << number << endl;
    } else if (type == 2) {
        if (!mem || !len) {
            fprintf(stderr, "\n( null )\n");
            return;
        }
        uint8_t* array = (uint8_t*)mem;
        fprintf(stderr, "%u bytes:\n{\n", len);
        uint32_t i = 0;
        for (i = 0; i < len - 1; i++) {
            fprintf(stderr, "0x%x, ", array[i]);
            if (i % 8 == 7)
                fprintf(stderr, "\n");
        }
        fprintf(stderr, "0x%x ", array[i]);
        fprintf(stderr, "\n}\n");
    }
}

#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
bool kmClient::maskGenerate()
{
    sgx_status_t retval;
    if (!enclave_trusted) {
        cerr << "KmClient : can't do mask generation before km_enclave trusted" << endl;
        return false;
    }
    sgx_status_t status;
    status = ecall_setNextEncryptionMask(_eid,
        &retval);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : ecall failed for mask generate, status = " << endl;
        sgxErrorReport(status);
        return false;
    }
    return true;
}

int kmClient::modifyClientStatus(int clientID, u_char* cipherBuffer, u_char* hmacBuffer)
{
    sgx_status_t retval;
    if (!enclave_trusted) {
        cerr << "KmClient : can't modify client status before km_enclave trusted" << endl;
        return -1;
    }
    sgx_status_t status;
    status = ecall_clientStatusModify(_eid,
        &retval,
        clientID,
        (uint8_t*)cipherBuffer,
        (uint8_t*)hmacBuffer);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : ecall failed for modify client list, status = " << endl;
        sgxErrorReport(status);
        return -1;
    } else {
        if (retval == SGX_ERROR_UNEXPECTED) {
            cerr << "KmClient : counter not correct, reset to 0" << endl;
            return CLIENT_COUNTER_REST; // reset counter
        } else if (retval == SGX_ERROR_INVALID_SIGNATURE) {
            cerr << "KmClient : client hmac not correct, require resend" << endl;
            return ERROR_RESEND; // resend message  (hmac not cpmpare)
        } else if (retval == SGX_SUCCESS) {
            cerr << "KmClient : init client info success" << endl;
            return SUCCESS; // success
        } else if (retval == SGX_ERROR_INVALID_PARAMETER) {
            cerr << "KmClient : nonce has been used, send regrenate message" << endl;
            return NONCE_HAS_USED;
        }
        return -1;
    }
}

bool kmClient::request(u_char* hash, int hashSize, u_char* key, int keySize, int clientID)
{
    sgx_status_t retval;
    if (!enclave_trusted) {
        cerr << "KmClient : can't do a request before km_enclave trusted" << endl;
        return false;
    }
    sgx_status_t status;
    uint8_t* ans = (uint8_t*)malloc(keySize);
    status = ecall_keygen_ctr(_eid,
        &retval,
        (uint8_t*)hash,
        (uint32_t)hashSize,
        ans,
        clientID);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : ecall failed for key generate, status = " << endl;
        sgxErrorReport(status);
        return false;
    } else if (retval == SGX_ERROR_INVALID_SIGNATURE) {
        cerr << "KmClient : client hash list hmac error, key generate failed" << endl;
        return false;
    }
    memcpy(key, ans, keySize);
    free(ans);
    return true;
}
#else
bool kmClient::request(u_char* hash, int hashSize, u_char* key, int keySize)
{
    sgx_status_t retval, status;
    if (!enclave_trusted) {
        cerr << "KmClient : can't do a request before pow_enclave trusted" << endl;
        return false;
    }
    uint8_t* ans = (uint8_t*)malloc(keySize);
    status = ecall_keygen(_eid,
        &retval,
        (uint8_t*)hash,
        (uint32_t)hashSize,
        ans);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : ecall failed for key generate, status = " << endl;
        sgxErrorReport(status);
        return false;
    } else if (retval == SGX_ERROR_INVALID_SIGNATURE) {
        cerr << "KmClient : client hash list hmac error, key generate failed" << endl;
        return false;
    }
    memcpy(key, ans, keySize);
    free(ans);
    return true;
}
#endif

kmClient::kmClient(string keyd, uint64_t keyRegressionMaxTimes)
{
    _keyd = keyd;
    keyRegressionMaxTimes_ = keyRegressionMaxTimes;
}

kmClient::~kmClient()
{
    sgx_status_t status;
    sgx_status_t retval;
    status = ecall_enclave_close(_eid, &retval);
    sgx_destroy_enclave(_eid);
}

bool kmClient::sessionKeyUpdate()
{
    sgx_status_t status, retval;
    status = ecall_setSessionKeyUpdate(_eid, &retval);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : session key regression ecall error, status = " << endl;
        sgxErrorReport(status);
        return false;
    } else {
#if SYSTEM_DEBUG_FLAG == 1
        char currentSessionKey[64];
        status = ecall_getCurrentSessionKey(_eid, &retval, currentSessionKey);
        cerr << "KmClient : Current session key = " << endl;
        PRINT_BYTE_ARRAY_KM(stdout, currentSessionKey, 32);
        cerr << "KmClient : Original session key = " << endl;
        PRINT_BYTE_ARRAY_KM(stdout, currentSessionKey + 32, 16);
        cerr << "KmClient : Original mac key = " << endl;
        PRINT_BYTE_ARRAY_KM(stdout, currentSessionKey + 48, 16);
#endif
        return true;
    }
}

bool kmClient::init(ssl* raSecurityChannel, SSL* sslConnection)
{
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
#endif
    _ctx = 0xdeadbeef;
    raSecurityChannel_ = raSecurityChannel;
    sslConnection_ = sslConnection;
    sgx_status_t status;
    sgx_status_t retval;
    raclose(_eid, _ctx);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartkmClient, NULL);
#endif
    status = ecall_enclave_close(_eid, &retval);
    sgx_destroy_enclave(_eid);
    enclave_trusted = doAttestation();
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKmClient, NULL);
    diff = 1000000 * (timeendKmClient.tv_sec - timestartkmClient.tv_sec) + timeendKmClient.tv_usec - timestartkmClient.tv_usec;
    second = diff / 1000000.0;
    cout << "KmClient : remote attestation time = " << second << " s" << endl;
#endif
    if (enclave_trusted) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartkmClient, NULL);
#endif
        status = ecall_setServerSecret(_eid,
            &retval,
            (uint8_t*)_keyd.c_str(),
            (uint32_t)_keyd.length());
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendKmClient, NULL);
        diff = 1000000 * (timeendKmClient.tv_sec - timestartkmClient.tv_sec) + timeendKmClient.tv_usec - timestartkmClient.tv_usec;
        second = diff / 1000000.0;
        cout << "KmClient : set key enclave global secret time = " << second << " s" << endl;
#endif
        if (status == SGX_SUCCESS) {
#if SYSTEM_DEBUG_FLAG == 1
            uint8_t ans[32];
            status = ecall_getServerSecret(_eid, &retval, ans);
            cerr << "KmClient : current server secret = " << endl;
            PRINT_BYTE_ARRAY_KM(stderr, ans, 32);
#endif
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartkmClient, NULL);
#endif
            uint32_t keyRegressionCounter = config.getKeyRegressionMaxTimes();
            status = ecall_setKeyRegressionCounter(_eid,
                &retval,
                keyRegressionCounter);
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendKmClient, NULL);
            diff = 1000000 * (timeendKmClient.tv_sec - timestartkmClient.tv_sec) + timeendKmClient.tv_usec - timestartkmClient.tv_usec;
            second = diff / 1000000.0;
            cout << "KmClient : set key regression max counter time = " << second << " s" << endl;
#endif
            if (status == SGX_SUCCESS) {
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartkmClient, NULL);
#endif
                status = ecall_setSessionKey(_eid,
                    &retval, &_ctx);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendKmClient, NULL);
                diff = 1000000 * (timeendKmClient.tv_sec - timestartkmClient.tv_sec) + timeendKmClient.tv_usec - timestartkmClient.tv_usec;
                second = diff / 1000000.0;
                cout << "KmClient : set key enclave session key time = " << second << " s" << endl;
#endif
                if (status == SGX_SUCCESS) {
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartkmClient, NULL);
#endif
                    status = ecall_setCTRMode(_eid, &retval);
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendKmClient, NULL);
                    diff = 1000000 * (timeendKmClient.tv_sec - timestartkmClient.tv_sec) + timeendKmClient.tv_usec - timestartkmClient.tv_usec;
                    second = diff / 1000000.0;
                    cout << "KmClient : init enclave ctr mode time = " << second << " s" << endl;
#endif
                    if (status == SGX_SUCCESS) {
                        return true;
                    } else {
                        cerr << "KmClient : set key server offline mask generate space error, status = " << endl;
                        sgxErrorReport(status);
                        return false;
                    }
#else
                    return true;
#endif
                } else {
                    cerr << "KmClient : set key server generate regression session key error, status = " << endl;
                    sgxErrorReport(status);
                    return false;
                }
            } else {
                cerr << "KmClient : set key server key regression max counter error, status = " << endl;
                sgxErrorReport(status);
                return false;
            }
        } else {
            cerr << "KmClient : set key server secret error, status = " << endl;
            sgxErrorReport(status);
            return false;
        }
    } else {
        cerr << "KmClient : enclave not trusted by storage server" << endl;
        return false;
    }
}

bool kmClient::createEnclave(sgx_enclave_id_t& eid,
    sgx_ra_context_t& ctx,
    string enclaveName)
{
    sgx_status_t status, retval, pse_status;

    status = sgx_create_enclave(enclaveName.c_str(),
        SGX_DEBUG_FLAG,
        &_token,
        &updated,
        &eid,
        0);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : create enclave error, status = " << endl;
        sgxErrorReport(status);
        return false;
    }
    status = enclave_ra_init(eid,
        &retval,
        def_service_public_key,
        false,
        &ctx,
        &pse_status);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : remote attestation ecall error, status = " << endl;
        sgxErrorReport(status);
        return false;
    } else if (!(retval && pse_status)) {
        cerr << "KmClient : remote attestation init enclave error" << endl;
        return false;
    }

    return true;
}

bool kmClient::getMsg01(sgx_enclave_id_t& eid,
    sgx_ra_context_t& ctx,
    string& msg01)
{
    uint32_t msg0;
    sgx_ra_msg1_t msg1;

    if (sgx_get_extended_epid_group_id(&msg0) != SGX_SUCCESS) {
        goto error;
    }

    if (sgx_ra_get_msg1(ctx, eid, sgx_ra_get_ga, &msg1) != SGX_SUCCESS) {
        goto error;
    }

    msg01.resize(sizeof msg0 + sizeof msg1);
    memcpy(&msg01[0], &msg1, sizeof msg1);
    memcpy(&msg01[sizeof msg1], &msg0, sizeof msg0);
    return true;

error:
    raclose(eid, ctx);
    return false;
}

bool kmClient::processMsg2(sgx_enclave_id_t& eid,
    sgx_ra_context_t& ctx,
    string& Msg2,
    string& Msg3)
{
    sgx_ra_msg3_t* msg3;
    uint32_t msg3_sz;
    sgx_ra_msg2_t* msg2 = (sgx_ra_msg2_t*)new uint8_t[Msg2.length()];
    memcpy(msg2, &Msg2[0], Msg2.length());
    if (sgx_ra_proc_msg2(ctx,
            eid,
            sgx_ra_proc_msg2_trusted,
            sgx_ra_get_msg3_trusted,
            msg2,
            sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
            &msg3,
            &msg3_sz)
        != SGX_SUCCESS) {
        goto error;
    }

    Msg3.resize(msg3_sz);
    memcpy(&Msg3[0], msg3, msg3_sz);
    return true;

error:
    raclose(eid, ctx);
    return false;
}

void kmClient::raclose(sgx_enclave_id_t& eid, sgx_ra_context_t& ctx)
{
    sgx_status_t status;
    enclave_ra_close(eid, &status, ctx);
}

bool kmClient::doAttestation()
{
    sgx_status_t status, sgxrv, pse_status;
    sgx_msg01_t msg01;
    sgx_ra_msg2_t* msg2;
    sgx_ra_msg3_t* msg3;
    ra_msg4_t* msg4 = NULL;
    uint32_t msg0_extended_epid_group_id = 0;
    uint32_t msg3_sz;

    string enclaveName = config.getKMEnclaveName();
    cerr << "KmClient : start to create enclave" << endl;
    status = sgx_create_enclave(enclaveName.c_str(), SGX_DEBUG_FLAG, &_token, &updated, &_eid, 0);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : Can not launch km_enclave : " << enclaveName << endl;
        sgxErrorReport(status);
        return false;
    }

    status = enclave_ra_init(_eid, &sgxrv, def_service_public_key, false,
        &_ctx, &pse_status);
    if (status != SGX_SUCCESS) {
        cerr << "KmClient : pow_enclave ra init failed, status =  " << endl;
        sgxErrorReport(status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS) {
        cerr << "KmClient : sgx ra init failed : " << sgxrv << endl;
        return false;
    }

    /* Generate msg0 */

    status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
    if (status != SGX_SUCCESS) {
        enclave_ra_close(_eid, &sgxrv, _ctx);
        cerr << "KmClient : sgx ge epid failed, status = " << endl;
        sgxErrorReport(status);
        return false;
    }

    /* Generate msg1 */

    status = sgx_ra_get_msg1(_ctx, _eid, sgx_ra_get_ga, &msg01.msg1);
    if (status != SGX_SUCCESS) {
        enclave_ra_close(_eid, &sgxrv, _ctx);
        cerr << "KmClient : sgx error get msg1, status = " << endl;
        sgxErrorReport(status);
        return false;
    }

    char msg01Buffer[sizeof(msg01)];
    memcpy(msg01Buffer, &msg01, sizeof(msg01));
    char msg2Buffer[SGX_MESSAGE_MAX_SIZE];
    int msg2RecvSize = 0;
    if (!raSecurityChannel_->send(sslConnection_, msg01Buffer, sizeof(msg01))) {
        cerr << "KmClient : msg01 send socket error" << endl;
        enclave_ra_close(_eid, &sgxrv, _ctx);
        return false;
    }
    if (!raSecurityChannel_->recv(sslConnection_, msg2Buffer, msg2RecvSize)) {
        cerr << "KmClient : msg2 recv socket error" << endl;
        enclave_ra_close(_eid, &sgxrv, _ctx);
        return false;
    }
    msg2 = (sgx_ra_msg2_t*)malloc(msg2RecvSize);
    memcpy(msg2, msg2Buffer, msg2RecvSize);
#if SYSTEM_DEBUG_FLAG == 1
    cout << "KmClient : Send msg01 and Recv msg2 success" << endl;
#endif
    /* Process Msg2, Get Msg3  */
    /* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

    status = sgx_ra_proc_msg2(_ctx, _eid,
        sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2,
        sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
        &msg3, &msg3_sz);

    if (status != SGX_SUCCESS) {
        enclave_ra_close(_eid, &sgxrv, _ctx);
        cerr << "KmClient : sgx_ra_proc_msg2 error, status = " << endl;
        sgxErrorReport(status);
        if (msg2 != nullptr) {
            free(msg2);
        }
        return false;
    } else {
        free(msg2);
    }

#if SYSTEM_DEBUG_FLAG == 1
    cout << "KmClient : process msg2 success" << endl;
#endif

    char msg3Buffer[msg3_sz];
    memcpy(msg3Buffer, msg3, msg3_sz);
    char msg4Buffer[SGX_MESSAGE_MAX_SIZE];
    int msg4RecvSize = 0;
    if (!raSecurityChannel_->send(sslConnection_, msg3Buffer, msg3_sz)) {
        cerr << "KmClient : msg3 send socket error" << endl;
        enclave_ra_close(_eid, &sgxrv, _ctx);
        return false;
    }

    if (!raSecurityChannel_->recv(sslConnection_, msg4Buffer, msg4RecvSize)) {
        cerr << "KmClient : msg4 recv socket error" << endl;
        enclave_ra_close(_eid, &sgxrv, _ctx);
        return false;
    }
    msg4 = (ra_msg4_t*)malloc(msg4RecvSize);
    memcpy(msg4, msg4Buffer, msg4RecvSize);
#if SYSTEM_DEBUG_FLAG == 1
    cout << "KmClient : send msg3 and Recv msg4 success" << endl;
#endif
    if (msg3 != nullptr) {
        free(msg3);
    }
    if (msg4->status) {
#if SYSTEM_DEBUG_FLAG == 1
        cout << "KmClient : Enclave TRUSTED" << endl;
#endif
    } else if (!msg4->status) {
        cerr << "KmClient : Enclave NOT TRUSTED" << endl;
        enclave_ra_close(_eid, &sgxrv, _ctx);
        free(msg4);
        return false;
    }

    enclave_trusted = msg4->status;
    free(msg4);
    return true;
}