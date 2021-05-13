#include "../include/powClient.hpp"
#include <sys/time.h>

using namespace std;

extern Configure config;

struct timeval timestartPowClient;
struct timeval timeendPowClient;

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

void PRINT_BYTE_ARRAY_POW_CLIENT(
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

void powClient::run()
{
#if SYSTEM_BREAK_DOWN == 1
    double powEnclaveCaluationTime = 0;
    double powExchangeInofrmationTime = 0;
    double powBuildHashListTime = 0;
    long diff;
    double second;
#endif
    vector<Data_t> batchChunk;
    uint64_t powBatchSize = config.getPOWBatchSize();
    u_char* batchChunkLogicDataCharBuffer;
    batchChunkLogicDataCharBuffer = (u_char*)malloc(sizeof(u_char) * (MAX_CHUNK_SIZE + sizeof(int)) * powBatchSize);
    memset(batchChunkLogicDataCharBuffer, 0, sizeof(u_char) * (MAX_CHUNK_SIZE + sizeof(int)) * powBatchSize);
    Data_t tempChunk;
    int netstatus;
    int currentBatchChunkNumber = 0;
    bool jobDoneFlag = false;
    uint32_t currentBatchSize = 0;
    batchChunk.clear();
    bool powRequestStatus = false;

    while (true) {

        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            jobDoneFlag = true;
        }
        if (extractMQ(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                senderObj_->insertMQ(tempChunk);
                continue;
            } else {
                batchChunk.push_back(tempChunk);
                memcpy(batchChunkLogicDataCharBuffer + currentBatchSize, &tempChunk.chunk.logicDataSize, sizeof(int));
                currentBatchSize += sizeof(int);
                memcpy(batchChunkLogicDataCharBuffer + currentBatchSize, tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize);
                currentBatchSize += tempChunk.chunk.logicDataSize;
                currentBatchChunkNumber++;
            }
        }
        if (currentBatchChunkNumber == powBatchSize || jobDoneFlag) {
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartPowClient, NULL);
#endif
            uint8_t clientMac[16];
            uint8_t chunkHashList[currentBatchChunkNumber * CHUNK_HASH_SIZE];
            memset(chunkHashList, 0, currentBatchChunkNumber * CHUNK_HASH_SIZE);
            powRequestStatus = this->request(batchChunkLogicDataCharBuffer, currentBatchSize, clientMac, chunkHashList);
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendPowClient, NULL);
            diff = 1000000 * (timeendPowClient.tv_sec - timestartPowClient.tv_sec) + timeendPowClient.tv_usec - timestartPowClient.tv_usec;
            second = diff / 1000000.0;
            powEnclaveCaluationTime += second;
#endif
            if (!powRequestStatus) {
                cerr << "PowClient : sgx request failed" << endl;
                break;
            } else {
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartPowClient, NULL);
#endif
                for (int i = 0; i < currentBatchChunkNumber; i++) {
                    memcpy(batchChunk[i].chunk.chunkHash, chunkHashList + i * CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
                }
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendPowClient, NULL);
                diff = 1000000 * (timeendPowClient.tv_sec - timestartPowClient.tv_sec) + timeendPowClient.tv_usec - timestartPowClient.tv_usec;
                second = diff / 1000000.0;
                powBuildHashListTime += second;
#endif
            }
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartPowClient, NULL);
#endif
            u_char serverResponse[sizeof(int) + sizeof(bool) * currentBatchChunkNumber];
            senderObj_->sendEnclaveSignedHash(clientMac, chunkHashList, currentBatchChunkNumber, serverResponse, netstatus);
#if SYSTEM_DEBUG_FLAG == 1
            cout << "PowClient : send signed hash list data = " << endl;
            PRINT_BYTE_ARRAY_POW_CLIENT(stderr, clientMac, 16);
            PRINT_BYTE_ARRAY_POW_CLIENT(stderr, chunkHashList, currentBatchChunkNumber * CHUNK_HASH_SIZE);
#endif
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendPowClient, NULL);
            diff = 1000000 * (timeendPowClient.tv_sec - timestartPowClient.tv_sec) + timeendPowClient.tv_usec - timestartPowClient.tv_usec;
            second = diff / 1000000.0;
            powExchangeInofrmationTime += second;
#endif
            if (netstatus != SUCCESS) {
                cerr << "PowClient : server pow signed hash verify error, client mac = " << endl;
                PRINT_BYTE_ARRAY_POW_CLIENT(stderr, clientMac, 16);
                PRINT_BYTE_ARRAY_POW_CLIENT(stderr, chunkHashList, CHUNK_HASH_SIZE);
                break;
            } else {
                int totalNeedChunkNumber;
                memcpy(&totalNeedChunkNumber, serverResponse, sizeof(int));
                bool requiredChunksList[currentBatchChunkNumber];
                memcpy(requiredChunksList, serverResponse + sizeof(int), sizeof(bool) * currentBatchChunkNumber);
#if SYSTEM_DEBUG_FLAG == 1
                cout << "PowClient : send pow signed hash for " << currentBatchChunkNumber << " chunks success, Server need " << totalNeedChunkNumber << " over all " << batchChunk.size() << endl;
#endif
                for (int i = 0; i < totalNeedChunkNumber; i++) {
                    if (requiredChunksList[i] == true) {
                        batchChunk[i].chunk.type = CHUNK_TYPE_NEED_UPLOAD;
                    }
                }
                int batchChunkSize = batchChunk.size();
                for (int i = 0; i < batchChunkSize; i++) {
                    senderObj_->insertMQ(batchChunk[i]);
                }
            }
            currentBatchChunkNumber = 0;
            currentBatchSize = 0;
            batchChunk.clear();
        }
        if (jobDoneFlag) {
            break;
        }
    }
    if (!senderObj_->editJobDoneFlag()) {
        cerr << "PowClient : error to set job done flag for sender" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    cout << "PowClient : enclave compute work time = " << powEnclaveCaluationTime << " s" << endl;
    cout << "PowClient : build hash list and insert hash to chunk time = " << powBuildHashListTime << " s" << endl;
    cout << "PowClient : exchange status to storage service provider time = " << powExchangeInofrmationTime << " s" << endl;
    cout << "PowClient : Total work time = " << powExchangeInofrmationTime + powEnclaveCaluationTime + powBuildHashListTime << " s" << endl;
#endif
    free(batchChunkLogicDataCharBuffer);
    return;
}

bool powClient::request(u_char* logicDataBatchBuffer, uint32_t bufferSize, uint8_t cmac[16], uint8_t* chunkHashList)
{
    sgx_status_t status, retval;
    status = ecall_calcmac(eid_, &retval, (uint8_t*)logicDataBatchBuffer, bufferSize, cmac, chunkHashList);
    if (status != SGX_SUCCESS) {
        cerr << "PowClient : ecall failed, status = " << endl;
        sgxErrorReport(status);
        return false;
    } else if (retval != SGX_SUCCESS) {
        cerr << "PowClient : pow compute error, retval = " << endl;
        sgxErrorReport(retval);
        return false;
    }
    return true;
}

bool powClient::loadSealedData()
{
    std::ifstream sealDataFile;
    if (sealDataFile.is_open()) {
        sealDataFile.close();
    }
    sealDataFile.open("pow-enclave.sealed", std::ios::binary);
    if (!sealDataFile.is_open()) {
        cerr << "PowClient : no sealed infomation, start remote attestation login" << endl;
        return false;
    } else {
        sealDataFile.seekg(0, ios_base::end);
        int sealedDataLength = sealDataFile.tellg();
        sealDataFile.seekg(0, ios_base::beg);
        char inPutDataBuffer[sealedDataLength];
        sealDataFile.read(inPutDataBuffer, sealedDataLength);
        if (sealDataFile.gcount() != sealedDataLength) {
            cerr << "PowClient : read sealed file error" << endl;
            return false;
        } else {
            sealDataFile.close();
            memcpy(sealedBuffer_, inPutDataBuffer, sealedDataLength);
            return true;
        }
    }
}

bool powClient::powEnclaveSealedInit()
{
    sgx_status_t status = SGX_SUCCESS;
    string enclaveName = config.getPOWEnclaveName();
    sgx_status_t retval;
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartEnclave;
    struct timeval timeendEnclave;
    long diff;
    double second;
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    status = sgx_create_enclave(enclaveName.c_str(), SGX_DEBUG_FLAG, NULL, NULL, &eid_, NULL);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : create enclave time = " << second << " s" << endl;
#endif
    if (status != SGX_SUCCESS) {
        cerr << "PowClient : create enclave error, eid = " << eid_ << endl;
        sgx_destroy_enclave(eid_);
        sgxErrorReport(status);
        return false;
    } else {
        cerr << "PowClient : create enclave done" << endl;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartEnclave, NULL);
#endif
        status = enclave_sealed_init(eid_, &retval, (uint8_t*)sealedBuffer_);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendEnclave, NULL);
        diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
        second = diff / 1000000.0;
        cout << "PowClient : sealed init enclave time = " << second << " s" << endl;
#endif
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "PowClient : unseal data size = " << sealedLen_ << "\t retval = " << retval << "\t status = " << status << endl;
#endif
        if (status == SGX_SUCCESS) {
#if SYSTEM_DEBUG_FLAG == 1
            cerr << "PowClient : unseal data ecall success, status = " << status << endl;
#endif
            if (retval != SGX_SUCCESS) {
                cerr << "PowClient : unseal data error, retval = " << retval << endl;
                sgx_destroy_enclave(eid_);
                return false;
            } else {
                return true;
            }
        } else {
            cerr << "PowClient : unseal data ecall error, status = " << status << endl;
            sgxErrorReport(status);
            sgx_destroy_enclave(eid_);
            return false;
        }
    }
}

bool powClient::powEnclaveSealedColse()
{
    sgx_status_t status;
    sgx_status_t retval;
    status = enclave_sealed_close(eid_, &retval, (uint8_t*)sealedBuffer_);
    if (status != SGX_SUCCESS) {
        cerr << "PowClient : seal data ecall error, status = " << endl;
        sgxErrorReport(status);
        return false;
    } else {
        if (retval != SGX_SUCCESS) {
            cerr << "PowClient : unseal data ecall return error, return value = " << retval << endl;
            return false;
        } else {
            return true;
        }
    }
}

bool powClient::outputSealedData()
{
    std::ofstream sealDataFile;
    if (sealDataFile.is_open()) {
        sealDataFile.close();
    }
    sealDataFile.open("pow-enclave.sealed", std::ofstream::out | std::ios::binary);
    if (sealDataFile.is_open()) {
        char outPutDataBuffer[sealedLen_];
        memcpy(outPutDataBuffer, sealedBuffer_, sealedLen_);
        sealDataFile.write(outPutDataBuffer, sealedLen_);
        sealDataFile.close();
        return true;
    } else {
        return false;
    }
}

powClient::powClient(Sender* senderObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    enclaveIsTrusted_ = false;
    ctx_ = 0xdeadbeef;
    senderObj_ = senderObjTemp;
    cryptoObj_ = new CryptoPrimitive();
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartEnclave;
    struct timeval timeendEnclave;
    long diff;
    double second;
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartPowClient, NULL);
#endif
#if ENCLAVE_SEALED_INIT_ENABLE == 1
    sealedLen_ = sizeof(sgx_sealed_data_t) + sizeof(sgx_ra_key_128_t);
    sealedBuffer_ = (char*)malloc(sealedLen_);
    memset(sealedBuffer_, -1, sealedLen_);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    bool loadSealedDataStatus = loadSealedData();
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    if (loadSealedDataStatus == true) {
        cout << "PowClient : load sealed information time = " << second << " s" << endl;
    }
#endif
    if (loadSealedDataStatus == true) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartEnclave, NULL);
#endif
        bool powEnclaveSealedInitStatus = powEnclaveSealedInit();
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendEnclave, NULL);
        diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
        second = diff / 1000000.0;
        cout << "PowClient : sealed init total work time = " << second << " s" << endl;
#endif
        if (powEnclaveSealedInitStatus == true) {
            cerr << "PowClient : enclave init via sealed data done" << endl;
            startMethod_ = 1;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartEnclave, NULL);
#endif
            bool loginToServerStatus = senderObj_->sendLogInMessage(CLIENT_SET_LOGIN_WITH_SEAL);
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendEnclave, NULL);
            diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
            second = diff / 1000000.0;
            cout << "PowClient : sealed init login ot storage server work time = " << second << " s" << endl;
#endif
            if (loginToServerStatus) {
                cerr << "PowClient : login to storage service provider success" << endl;
            } else {
                cerr << "PowClient : login to storage service provider error" << endl;
            }
#if SYSTEM_DEBUG_FLAG == 1
            sgx_status_t status, retval;
            cerr << "PowClient : ecall get session key success, key = " << endl;
            char currentSessionKey[16];
            status = ecall_getCurrentSessionKey(eid_, &retval, currentSessionKey);
            PRINT_BYTE_ARRAY_POW_CLIENT(stdout, currentSessionKey, 16);
#endif
        } else {
            cerr << "PowClient : enclave init via sealed data error" << endl;
            sgx_destroy_enclave(eid_);
            exit(0);
        }
    } else {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartEnclave, NULL);
#endif
        senderObj_->sendLogOutMessage();
        bool sendLoginMessageStatus = senderObj_->sendLogInMessage(CLIENT_SET_LOGIN);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendEnclave, NULL);
        diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
        second = diff / 1000000.0;
        cout << "PowClient : remote attestation init login ot storage server work time = " << second << " s" << endl;
#endif
        if (sendLoginMessageStatus) {
            cerr << "PowClient : login to storage service provider success" << endl;
        } else {
            cerr << "PowClient : login to storage service provider error" << endl;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartEnclave, NULL);
#endif
        bool remoteAttestationStatus = this->do_attestation();
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendEnclave, NULL);
        diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
        second = diff / 1000000.0;
        cout << "PowClient : remote attestation init total work time = " << second << " s" << endl;
#endif
        if (!remoteAttestationStatus) {
            cerr << "PowClient : enclave init via remote attestation error" << endl;
            exit(0);
        } else {
            sgx_status_t retval;
            sgx_status_t status;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartEnclave, NULL);
#endif
            status = ecall_setSessionKey(eid_, &retval, &ctx_, SGX_RA_KEY_SK);
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendEnclave, NULL);
            diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
            second = diff / 1000000.0;
            cout << "PowClient : set up remote attestation session key time = " << second << " s" << endl;
#endif
            if (status != SGX_SUCCESS) {
                cerr << "PowClient : ecall set session key failed, status = " << endl;
                sgxErrorReport(status);
                exit(0);
            } else {
                startMethod_ = 2;
#if SYSTEM_DEBUG_FLAG == 1
                cerr << "PowClient : ecall set session key success, key = " << endl;
                char currentSessionKey[16];
                status = ecall_getCurrentSessionKey(eid_, &retval, currentSessionKey);
                PRINT_BYTE_ARRAY_POW_CLIENT(stdout, currentSessionKey, 16);
#endif
            }
        }
    }
#else
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    senderObj_->sendLogOutMessage();
    bool sendLoginToStorageServerStatus = senderObj_->sendLogInMessage(CLIENT_SET_LOGIN);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : remote attestation init login ot storage server work time = " << second << " s" << endl;
#endif
    if (sendLoginToStorageServerStatus) {
        cerr << "PowClient : login to storage service provider success" << endl;
    } else {
        cerr << "PowClient : login to storage service provider error" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    bool remoteAttestationStatus = this->do_attestation();
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : remote attestation init total work time = " << second << " s" << endl;
#endif
    if (!remoteAttestationStatus) {
        cerr << "PowClient : enclave init via remote attestation error" << endl;
        exit(0);
    } else {
        sgx_status_t retval;
        sgx_status_t status;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartEnclave, NULL);
#endif
        status = ecall_setSessionKey(eid_, &retval, &ctx_, SGX_RA_KEY_SK);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendEnclave, NULL);
        diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
        second = diff / 1000000.0;
        cout << "PowClient : set up remote attestation session key time = " << second << " s" << endl;
#endif
        if (status != SGX_SUCCESS) {
            cerr << "PowClient : ecall set session key failed, status = " << endl;
            sgxErrorReport(status);
            exit(0);
        } else {
            startMethod_ = 2;
#if SYSTEM_DEBUG_FLAG == 1
            cerr << "PowClient : ecall set session key success, key = " << endl;
            char currentSessionKey[16];
            status = ecall_getCurrentSessionKey(eid_, &retval, currentSessionKey);
            PRINT_BYTE_ARRAY_POW_CLIENT(stdout, currentSessionKey, 16);
#endif
        }
    }
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendPowClient, NULL);
    diff = 1000000 * (timeendPowClient.tv_sec - timestartPowClient.tv_sec) + timeendPowClient.tv_usec - timestartPowClient.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : enclave init time = " << second << " s" << endl;
#endif
}

powClient::~powClient()
{
    inputMQ_->~messageQueue();
    delete inputMQ_;
    delete cryptoObj_;
#if ENCLAVE_SEALED_INIT_ENABLE == 1
    if (startMethod_ == 2) {
        if (powEnclaveSealedColse() == true) {
            if (outputSealedData() == true) {
                cerr << "PowClient : enclave sealing done" << endl;
            } else {
                cerr << "PowClient : enclave sealing error" << endl;
            }
        } else {
            cerr << "PowClient : enclave sealing error" << endl;
        }
    }
    free(sealedBuffer_);
#endif
    sgx_status_t ret;
    ret = sgx_destroy_enclave(eid_);
    if (ret != SGX_SUCCESS) {
        cerr << "PowClient : enclave clean up error" << endl;
    }
}

bool powClient::do_attestation()
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartEnclave;
    struct timeval timeendEnclave;
    long diff;
    double second;
#endif
    sgx_status_t status, sgxrv, pse_status;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t* msg2;
    sgx_ra_msg3_t* msg3;
    ra_msg4_t* msg4 = NULL;
    uint32_t msg0_extended_epid_group_id = 0;
    uint32_t msg3Size;
    string enclaveName = config.getPOWEnclaveName();

#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    status = sgx_create_enclave(enclaveName.c_str(), SGX_DEBUG_FLAG, NULL, NULL, &eid_, NULL);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : create enclave time = " << second << " s" << endl;
#endif
    cerr << "PowClient : create pow enclave done" << endl;
    if (status != SGX_SUCCESS) {
        cerr << "PowClient : Can not launch pow_enclave : " << enclaveName << endl;
        sgxErrorReport(status);
        return false;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartEnclave, NULL);
#endif
    status = enclave_ra_init(eid_, &sgxrv, def_service_public_key, false, &ctx_, &pse_status);
    if (status != SGX_SUCCESS) {
        cerr << "PowClient : pow_enclave ra init failed, status =  " << endl;
        sgxErrorReport(status);
        return false;
    }

    if (sgxrv != SGX_SUCCESS) {
        cerr << "PowClient : sgx ra init failed : " << sgxrv << endl;
        return false;
    }

    /* Generate msg0 */

    status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
    if (status != SGX_SUCCESS) {
        enclave_ra_close(eid_, &sgxrv, ctx_);
        cerr << "PowClient : sgx get epid failed, status = " << endl;
        sgxErrorReport(status);
        return false;
    }
    /* Generate msg1 */

    status = sgx_ra_get_msg1(ctx_, eid_, sgx_ra_get_ga, &msg1);
    if (status != SGX_SUCCESS) {
        enclave_ra_close(eid_, &sgxrv, ctx_);
        cerr << "PowClient : sgx error get msg1, status = " << endl;
        sgxErrorReport(status);
        return false;
    }

    int netstatus;
    if (!senderObj_->sendSGXmsg01(msg0_extended_epid_group_id, msg1, msg2, netstatus)) {
        cerr << "PowClient : send msg01 error : " << netstatus << endl;
        enclave_ra_close(eid_, &sgxrv, ctx_);
        return false;
    }

    status = sgx_ra_proc_msg2(ctx_, eid_, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size, &msg3, &msg3Size);

    if (status != SGX_SUCCESS) {
        cerr << "PowClient : error process msg 2, status = " << endl;
        sgxErrorReport(status);
        enclave_ra_close(eid_, &sgxrv, ctx_);
    }

    free(msg2);

    if (!senderObj_->sendSGXmsg3(msg3, msg3Size, msg4, netstatus)) {
        enclave_ra_close(eid_, &sgxrv, ctx_);
        cerr << "PowClient : error send msg3 & get back msg4: " << netstatus << endl;
        return false;
    }
    free(msg3);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendEnclave, NULL);
    diff = 1000000 * (timeendEnclave.tv_sec - timestartEnclave.tv_sec) + timeendEnclave.tv_usec - timestartEnclave.tv_usec;
    second = diff / 1000000.0;
    cout << "PowClient : remote attestation init enclave time = " << second << " s" << endl;
#endif
    if (!msg4->status) {
        cerr << "PowClient : Enclave NOT TRUSTED" << endl;
        enclave_ra_close(eid_, &sgxrv, ctx_);
        free(msg4);
        return false;
    } else {
        enclaveIsTrusted_ = msg4->status;
        free(msg4);
        return true;
    }
}

bool powClient::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}

bool powClient::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool powClient::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}