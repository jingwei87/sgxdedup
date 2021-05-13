#include "keyClient.hpp"
#include "openssl/rsa.h"
#include <sys/time.h>

extern Configure config;

struct timeval timestartKey;
struct timeval timeendKey;

void PRINT_BYTE_ARRAY_KEY_CLIENT(
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

KeyClient::KeyClient(powClient* powObjTemp, u_char* keyExchangeKey)
{
    inputMQ_ = new messageQueue<Data_t>;
    powObj_ = powObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    memcpy(keyExchangeKey_, keyExchangeKey, KEY_SERVER_SESSION_KEY_SIZE);
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    clientID_ = config.getClientID();
}

KeyClient::KeyClient(u_char* keyExchangeKey, int threadNumber, uint64_t keyGenNumber, int batchSize)
{
    inputMQ_ = new messageQueue<Data_t>;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    memcpy(keyExchangeKey_, keyExchangeKey, KEY_SERVER_SESSION_KEY_SIZE);
    keyGenNumber_ = keyGenNumber;
    totalSimulatorThreadNumber_ = threadNumber;
    currentInitThreadNumber_ = 0;
    clientID_ = config.getClientID();
    batchNumber_ = batchSize;
}

KeyClient::~KeyClient()
{
    delete cryptoObj_;
    inputMQ_->~messageQueue();
    delete inputMQ_;
}

bool KeyClient::outputKeyGenSimulatorRunningTime()
{
    uint64_t startTime = ~0, endTime = 0;
    if (keyGenSimulatorStartTimeCounter_.size() != keyGenSimulatorEndTimeCounter_.size()) {
        cerr << "KeyClient : key generate simulator time counter error" << endl;
        return false;
    }
    for (int i = 0; i < keyGenSimulatorStartTimeCounter_.size(); i++) {
        uint64_t startTimeTemp = 1000000 * keyGenSimulatorStartTimeCounter_[i].tv_sec + keyGenSimulatorStartTimeCounter_[i].tv_usec;
        uint64_t endTimeTemp = 1000000 * keyGenSimulatorEndTimeCounter_[i].tv_sec + keyGenSimulatorEndTimeCounter_[i].tv_usec;
        if (startTimeTemp < startTime) {
            startTime = startTimeTemp;
        }
        if (endTimeTemp > endTime) {
            endTime = endTimeTemp;
        }
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "Time Count : " << startTime << "\t" << startTimeTemp << "\t" << endTime << "\t" << endTimeTemp << endl;
#endif
    }
    double second = (endTime - startTime) / 1000000.0;
    cout << "KeyClient : key generate simulator working time = " << second << endl;
    // #if SYSTEM_BREAK_DOWN == 1
    //     cout << "KeyClient : key exchange encryption work time = " << keyExchangeEncTime << " s" << endl;
    // #if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    //     cout << "KeyClient : key exchange mask generate work time = " << keyExchangeMaskGenerateTime << " s" << endl;
    // #endif
    // #endif
    return true;
}

#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR

bool KeyClient::initClientCTRInfo()
{
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey, NULL);
#endif // SYSTEM_BREAK_DOWN
    //read old counter
    string keyGenFileName = ".keyGenStore";
    ifstream keyGenStoreIn;
    keyGenStoreIn.open(keyGenFileName, std::ifstream::in | std::ifstream::binary);
    if (keyGenStoreIn.is_open()) {
        keyGenStoreIn.seekg(0, ios_base::end);
        int counterFileSize = keyGenStoreIn.tellg();
        keyGenStoreIn.seekg(0, ios_base::beg);
        if (counterFileSize != 16) {
            cerr << "KeyClient : stored old counter file size error" << endl;
            return false;
        } else {
            char readBuffer[16];
            keyGenStoreIn.read(readBuffer, 16);
            keyGenStoreIn.close();
            if (keyGenStoreIn.gcount() != 16) {
                cerr << "KeyClient : read old counter file size error" << endl;
            } else {
                memcpy(nonce_, readBuffer, 12);
                memcpy(&counter_, readBuffer + 12, sizeof(uint32_t));
#if SYSTEM_DEBUG_FLAG == 1
                cerr << "KeyClient : Read old counter file : " << keyGenFileName << " success, the original counter = " << counter_ << ", nonce = " << endl;
                PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, nonce_, 12);
#endif
            }
        }
    } else {
    nonceUsedRetry:
#if MULTI_CLIENT_UPLOAD_TEST == 1
        memset(nonce_, clientID_, 12);
#else
        srand(time(NULL));
        for (int i = 0; i < 12 / sizeof(int); i++) {
            int randomNumber = rand();
            memcpy(nonce_ + i * sizeof(int), &randomNumber, sizeof(int));
        }
#endif
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyClient : Can not open old counter file : \"" << keyGenFileName << "\", Directly reset counter to 0, generate nonce = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, nonce_, 12);
#endif
    }
    // done
    NetworkHeadStruct_t initHead, responseHead;
    initHead.clientID = clientID_;
    initHead.dataSize = 48;
    initHead.messageType = KEY_GEN_UPLOAD_CLIENT_INFO;
    char initInfoBuffer[sizeof(NetworkHeadStruct_t) + initHead.dataSize]; // clientID & nonce & counter
    char responseBuffer[sizeof(NetworkHeadStruct_t)];
    memcpy(initInfoBuffer, &initHead, sizeof(NetworkHeadStruct_t));
    u_char tempCipherBuffer[16], tempPlaintBuffer[16];
    memcpy(tempPlaintBuffer, &counter_, sizeof(uint32_t));
    memcpy(tempPlaintBuffer + sizeof(uint32_t), nonce_, 16 - sizeof(uint32_t));
    cryptoObj_->keyExchangeEncrypt(tempPlaintBuffer, 16, keyExchangeKey_, keyExchangeKey_, tempCipherBuffer);
    memcpy(initInfoBuffer + sizeof(NetworkHeadStruct_t), tempCipherBuffer, 16);
    cryptoObj_->sha256Hmac(tempCipherBuffer, 16, (u_char*)initInfoBuffer + sizeof(NetworkHeadStruct_t) + 16, keyExchangeKey_, 32);
    if (!keySecurityChannel_->send(sslConnection_, initInfoBuffer, sizeof(NetworkHeadStruct_t) + initHead.dataSize)) {
        cerr << "KeyClient: send init information error" << endl;
        return false;
    } else {
        int recvSize;
        if (!keySecurityChannel_->recv(sslConnection_, responseBuffer, recvSize)) {
            cerr << "KeyClient: recv init information status error" << endl;
            return false;
        } else {
            memcpy(&responseHead, responseBuffer, sizeof(NetworkHeadStruct_t));
#if SYSTEM_DEBUG_FLAG == 1
            cerr << "KeyClient : recv key server response, message type = " << responseHead.messageType << endl;
            PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, responseBuffer, sizeof(NetworkHeadStruct_t));
#endif
            if (responseHead.messageType == CLIENT_COUNTER_REST) {
                cerr << "KeyClient : key server counter error, reset client counter to 0" << endl;
                counter_ = 0;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendKey, NULL);
                int diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                double second = diff / 1000000.0;
                cout << "KeyClient : init ctr mode key exchange time = " << second << " s" << endl;
#endif // SYSTEM_BREAK_DOWN
                return true;
            } else if (responseHead.messageType == NONCE_HAS_USED) {
                cerr << "KeyClient: nonce has used, goto retry" << endl;
                goto nonceUsedRetry;
            } else if (responseHead.messageType == ERROR_RESEND) {
                cerr << "KeyClient: hmac error, goto retry" << endl;
                goto nonceUsedRetry;
            } else if (responseHead.messageType == SUCCESS) {
                cerr << "KeyClient : init information success, start key generate" << endl;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendKey, NULL);
                int diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                double second = diff / 1000000.0;
                cout << "KeyClient : init ctr mode key exchange time = " << second << " s" << endl;
#endif // SYSTEM_BREAK_DOWN
                return true;
            }
        }
    }
}

bool KeyClient::saveClientCTRInfo()
{
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey, NULL);
#endif // SYSTEM_BREAK_DOWN
    string keyGenFileName = ".keyGenStore";
    ofstream counterOut;
    counterOut.open(keyGenFileName, std::ofstream::out | std::ofstream::binary);
    if (!counterOut.is_open()) {
        cerr << "KeyClient : Can not open counter store file : " << keyGenFileName << endl;
        return false;
    } else {
        char writeBuffer[16];
        memcpy(writeBuffer, nonce_, 12);
        memcpy(writeBuffer + 12, &counter_, sizeof(uint32_t));
        counterOut.write(writeBuffer, 16);
        counterOut.close();
        cerr << "KeyClient : Stored current counter file : " << keyGenFileName << endl;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendKey, NULL);
        int diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
        double second = diff / 1000000.0;
        cout << "KeyClient : save ctr mode status time = " << second << " s" << endl;
#endif // SYSTEM_BREAK_DOWN
        return true;
    }
}

#endif

void KeyClient::runKeyGenSimulator(int clientID)
{
    struct timeval timestartKeySimulatorThread;
    struct timeval timeendKeySimulatorThread;
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartKeySimulator;
    struct timeval timeendKeySimulator;
    double threadWorkTime = 0;
    double keyGenTime = 0;
    double chunkHashGenerateTime = 0;
    double keyExchangeTime = 0;
    long diff;
    double second;
#endif
    CryptoPrimitive* cryptoObj = new CryptoPrimitive();
    ssl* keySecurityChannel = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    SSL* sslConnection = keySecurityChannel->sslConnect().second;
    int batchNumber = 0;
    uint64_t currentKeyGenNumber = 0;
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE * batchNumber_];
    u_char chunkHash[CHUNK_HASH_SIZE * batchNumber_];
    bool JobDoneFlag = false;
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKeySimulator, NULL);
#endif
    u_char nonce[CRYPTO_BLOCK_SZIE - sizeof(uint32_t)];
    uint32_t counter = 0;
    //read old counter
    string keyGenFileName = ".keyGenStore" + to_string(clientID);
    ifstream keyGenStoreIn;
    keyGenStoreIn.open(keyGenFileName, std::ifstream::in | std::ifstream::binary);
    if (keyGenStoreIn.is_open()) {
        keyGenStoreIn.seekg(0, ios_base::end);
        int counterFileSize = keyGenStoreIn.tellg();
        keyGenStoreIn.seekg(0, ios_base::beg);
        if (counterFileSize != 16) {
            cerr << "KeyClient : stored old counter file size error, size = " << counterFileSize << endl;
        } else {
            char readBuffer[16];
            keyGenStoreIn.read(readBuffer, 16);
            keyGenStoreIn.close();
            if (keyGenStoreIn.gcount() != 16) {
                cerr << "KeyClient : read old counter file size error" << endl;
            } else {
                memcpy(nonce, readBuffer, 12);
                memcpy(&counter, readBuffer + 12, sizeof(uint32_t));
#if SYSTEM_DEBUG_FLAG == 1
                cerr << "KeyClient : Read old counter file : " << keyGenFileName << " success, the original counter = " << counter << ", nonce = " << endl;
                PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, nonce, 12);
#endif
            }
        }
    } else {
    nonceUsedRetry:
        // srand(time(NULL));
        // for (int i = 0; i < 12 / sizeof(int); i++) {
        //     int randomNumber = rand();
        //     memcpy(nonce + i * sizeof(int), &randomNumber, sizeof(int));
        // }
        memset(nonce, clientID, 12);
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyClient : Can not open old counter file : \"" << keyGenFileName << "\", Directly reset counter to 0, generate nonce = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, nonce, 12);
#endif
    }
    // done
    NetworkHeadStruct_t initHead, responseHead;
    initHead.clientID = clientID;
    initHead.dataSize = 48;
    initHead.messageType = KEY_GEN_UPLOAD_CLIENT_INFO;
    char initInfoBuffer[sizeof(NetworkHeadStruct_t) + initHead.dataSize]; // clientID & nonce & counter
    char responseBuffer[sizeof(NetworkHeadStruct_t)];
    memcpy(initInfoBuffer, &initHead, sizeof(NetworkHeadStruct_t));
    u_char tempCipherBuffer[16], tempPlaintBuffer[16];
    memcpy(tempPlaintBuffer, &counter, sizeof(uint32_t));
    memcpy(tempPlaintBuffer + sizeof(uint32_t), nonce, 16 - sizeof(uint32_t));
    cryptoObj->keyExchangeEncrypt(tempPlaintBuffer, 16, keyExchangeKey_, keyExchangeKey_, tempCipherBuffer);
    memcpy(initInfoBuffer + sizeof(NetworkHeadStruct_t), tempCipherBuffer, 16);
    cryptoObj->sha256Hmac(tempCipherBuffer, 16, (u_char*)initInfoBuffer + sizeof(NetworkHeadStruct_t) + 16, keyExchangeKey_, 32);
    if (!keySecurityChannel->send(sslConnection, initInfoBuffer, sizeof(NetworkHeadStruct_t) + initHead.dataSize)) {
        cerr << "KeyClient: send init information error" << endl;
        return;
    } else {
        int recvSize;
        if (!keySecurityChannel->recv(sslConnection, responseBuffer, recvSize)) {
            cerr << "KeyClient: recv init information status error" << endl;
            return;
        } else {
            memcpy(&responseHead, responseBuffer, sizeof(NetworkHeadStruct_t));
            if (responseHead.messageType == CLIENT_COUNTER_REST) {
                cerr << "KeyClient : key server counter error, reset client counter to 0" << endl;
                counter = 0;
            } else if (responseHead.messageType == NONCE_HAS_USED) {
                cerr << "KeyClient: nonce has used, goto retry" << endl;
                goto nonceUsedRetry;
            } else if (responseHead.messageType == ERROR_RESEND) {
                cerr << "KeyClient: hmac error, goto retry" << endl;
                goto nonceUsedRetry;
            }
        }
        cerr << "KeyClient : init information success, start key generate" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKeySimulator, NULL);
#endif
    mutexkeyGenerateSimulatorStart_.lock();
    currentInitThreadNumber_++;
#if SYSTEM_BREAK_DOWN == 1
    diff = 1000000 * (timeendKeySimulator.tv_sec - timestartKeySimulator.tv_sec) + timeendKeySimulator.tv_usec - timestartKeySimulator.tv_usec;
    second = diff / 1000000.0;
    // cout << "KeyClient : init ctr mode for client " << clientID << " time = " << second << " s" << endl;
#endif
    mutexkeyGenerateSimulatorStart_.unlock();
    while (true) {
        // cout << "Client ID = " << clientID << ", thread number = " << currentInitThreadNumber_ << endl;
        boost::xtime xt;
        boost::xtime_get(&xt, boost::TIME_UTC_);
        xt.sec += 1;
        boost::thread::sleep(xt);
        if (currentInitThreadNumber_ == totalSimulatorThreadNumber_) {
            break;
        }
    }
#endif

    NetworkHeadStruct_t dataHead;
    dataHead.clientID = clientID;
    dataHead.messageType = KEY_GEN_UPLOAD_CHUNK_HASH;
    u_char chunkHashTemp[CHUNK_HASH_SIZE];
    memset(chunkHashTemp, 1, CHUNK_HASH_SIZE);

    gettimeofday(&timestartKeySimulatorThread, NULL);

    while (true) {

        if (currentKeyGenNumber < keyGenNumber_) {
            memcpy(chunkHash + batchNumber * CHUNK_HASH_SIZE, chunkHashTemp, CHUNK_HASH_SIZE);
            batchNumber++;
            currentKeyGenNumber++;
        } else {
            JobDoneFlag = true;
        }

        if (batchNumber == batchNumber_ || JobDoneFlag) {
            if (batchNumber == 0) {
                break;
            }
            int batchedKeySize = 0;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartKeySimulator, NULL);
#endif
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
            dataHead.dataSize = batchNumber * CHUNK_HASH_SIZE;
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize, keySecurityChannel, sslConnection, cryptoObj, nonce, counter, dataHead);
            counter += batchNumber * 4;
#elif KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CFB
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize, keySecurityChannel, sslConnection, cryptoObj);
#endif
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendKeySimulator, NULL);
            diff = 1000000 * (timeendKeySimulator.tv_sec - timestartKeySimulator.tv_sec) + timeendKeySimulator.tv_usec - timestartKeySimulator.tv_usec;
            second = diff / 1000000.0;
            keyExchangeTime += second;
            keyGenTime += second;
#endif
            memset(chunkHash, 0, CHUNK_HASH_SIZE * batchNumber_);
            memset(chunkKey, 0, CHUNK_HASH_SIZE * batchNumber_);
            batchNumber = 0;
            if (keyExchangeStatus == false) {
                cerr << "KeyClient : key generate error, thread exit" << endl;
                break;
            }
        }
        if (JobDoneFlag) {
            break;
        }
    }

    gettimeofday(&timeendKeySimulatorThread, NULL);
#if SYSTEM_BREAK_DOWN == 1
    diff = 1000000 * (timeendKeySimulatorThread.tv_sec - timestartKeySimulatorThread.tv_sec) + timeendKeySimulatorThread.tv_usec - timestartKeySimulatorThread.tv_usec;
    second = diff / 1000000.0;
    threadWorkTime += second;
#endif

#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    ofstream counterOut;
    mutexkeyGenerateSimulatorStart_.lock();
    counterOut.open(keyGenFileName, std::ofstream::out | std::ofstream::binary);
    if (!counterOut.is_open()) {
        cerr << "KeyClient : Can not open counter store file : " << keyGenFileName << endl;
    } else {
        char writeBuffer[16];
        memcpy(writeBuffer, nonce, 12);
        memcpy(writeBuffer + 12, &counter, sizeof(uint32_t));
        counterOut.write(writeBuffer, 16);
        counterOut.close();
        cerr << "KeyClient : Stored current counter file : " << keyGenFileName << ", counter = " << counter << endl;
    }
    mutexkeyGenerateSimulatorStart_.unlock();
#endif
    mutexkeyGenerateSimulatorStart_.lock();
    keyGenSimulatorStartTimeCounter_.push_back(timestartKeySimulatorThread);
    keyGenSimulatorEndTimeCounter_.push_back(timeendKeySimulatorThread);
    // #if SYSTEM_BREAK_DOWN == 1
    //     cout << "KeyClient : client ID = " << clientID << endl;
    //     cout << "KeyClient : key generate work time = " << keyGenTime << " s, total key generated is " << currentKeyGenNumber << endl;
    //     cout << "KeyClient : key exchange work time = " << keyExchangeTime << " s, chunk hash generate time is " << chunkHashGenerateTime << " s" << endl;
    //     cout << "KeyClient : simulator thread work time =  " << threadWorkTime << " s" << endl;
    // // #if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    // //     cout << "KeyClient : key exchange mask generate work time = " << keyExchangeMaskGenerateTime << " s" << endl;
    // // #endif
    // #endif
    mutexkeyGenerateSimulatorStart_.unlock();
    delete cryptoObj;
    free(sslConnection);
    delete keySecurityChannel;
    return;
}

void KeyClient::run()
{

#if SYSTEM_BREAK_DOWN == 1
    double keyGenTime = 0;
    double chunkContentEncryptionTime = 0;
    long diff;
    double second;
#endif // SYSTEM_BREAK_DOWN
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    bool initStatus = initClientCTRInfo();
    if (initStatus != true) {
        cerr << "KeyClient : init to key server error, client exit" << endl;
        exit(0);
    }
#if SYSTEM_DEBUG_FLAG == 1
    else {
        cerr << "KeyClient : init to key server success" << endl;
    }
#endif
#endif
    vector<Data_t> batchList;
    int batchNumber = 0;
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_];
    u_char chunkHash[CHUNK_HASH_SIZE * keyBatchSize_];
    bool JobDoneFlag = false;
    NetworkHeadStruct_t dataHead;
    dataHead.clientID = clientID_;
    dataHead.messageType = KEY_GEN_UPLOAD_CHUNK_HASH;
    while (true) {
        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            JobDoneFlag = true;
        }
        if (extractMQ(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                powObj_->insertMQ(tempChunk);
                continue;
            }
            batchList.push_back(tempChunk);
            memcpy(chunkHash + batchNumber * CHUNK_HASH_SIZE, tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
            batchNumber++;
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
            if (batchNumber == 0) {
                bool editJobDoneFlagStatus = powObj_->editJobDoneFlag();
                if (!editJobDoneFlagStatus) {
                    cerr << "KeyClient : error to set job done flag for encoder" << endl;
                }
                break;
            }
            int batchedKeySize = 0;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartKey, NULL);
#endif
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
            dataHead.dataSize = batchNumber * CHUNK_HASH_SIZE;
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize, dataHead);
            counter_ += batchNumber * 4;
#else
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize);
#endif

#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
#endif
            if (!keyExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                for (int i = 0; i < batchNumber; i++) {
                    memcpy(batchList[i].chunk.encryptKey, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
#if SYSTEM_DEBUG_FLAG == 1
                    cerr << "KeyClient : chunk " << batchList[i].chunk.ID << ", encrypt key = " << endl;
                    PRINT_BYTE_ARRAY_KEY_CLIENT(stdout, batchList[i].chunk.encryptKey, 32);
#endif
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    u_char ciphertext[batchList[i].chunk.logicDataSize];
                    bool encryptChunkContentStatus = cryptoObj_->encryptWithKey(batchList[i].chunk.logicData, batchList[i].chunk.logicDataSize, batchList[i].chunk.encryptKey, ciphertext);
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    chunkContentEncryptionTime += second;
#endif
                    if (!encryptChunkContentStatus) {
                        cerr << "KeyClient : cryptoPrimitive error, encrypt chunk logic data error" << endl;
                        return;
                    } else {
                        memcpy(batchList[i].chunk.logicData, ciphertext, batchList[i].chunk.logicDataSize);
                    }
                    powObj_->insertMQ(batchList[i]);
                }
                batchList.clear();
                memset(chunkHash, 0, CHUNK_HASH_SIZE * keyBatchSize_);
                memset(chunkKey, 0, CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_);
                batchNumber = 0;
            }
        }
        if (JobDoneFlag) {
            bool editJobDoneFlagStatus = powObj_->editJobDoneFlag();
            if (!editJobDoneFlagStatus) {
                cerr << "KeyClient : error to set job done flag for encoder" << endl;
            }
            break;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    cout << "KeyClient : key exchange mask generate work time = " << keyExchangeMaskGenerateTime << " s" << endl;
#endif
    cout << "KeyClient : key exchange encrypt/decrypt work time = " << keyExchangeEncTime << " s" << endl;
    cout << "KeyClient : key generate total work time = " << keyGenTime << " s" << endl;
    cout << "KeyClient : chunk encryption work time = " << chunkContentEncryptionTime << " s" << endl;
#endif
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    bool saveStatus = saveClientCTRInfo();
    if (saveStatus != true) {
        cerr << "KeyClient : save ctr mode information error" << endl;
        exit(0);
    }
#if SYSTEM_DEBUG_FLAG == 1
    else {
        cerr << "KeyClient : save ctr mode information success" << endl;
    }
#endif
#endif
    return;
}

#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CFB
bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber)
{
    u_char sendHash[CHUNK_HASH_SIZE * batchNumber + 32];
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartKey_enc;
    struct timeval timeendKey_enc;
    gettimeofday(&timestartKey_enc, NULL);
#endif
    cryptoObj_->keyExchangeEncrypt(batchHashList, batchNumber * CHUNK_HASH_SIZE, keyExchangeKey_, keyExchangeKey_, sendHash);
    cryptoObj_->sha256Hmac(sendHash, CHUNK_HASH_SIZE * batchNumber, sendHash + CHUNK_HASH_SIZE * batchNumber, keyExchangeKey_, 32);
#if SYSTEM_DEBUG_FLAG == 1
    cerr << "KeyClient : send key exchange hmac = " << endl;
    PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, sendHash + CHUNK_HASH_SIZE * batchNumber, 32);
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKey_enc, NULL);
    long diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    double second = diff / 1000000.0;
    keyExchangeEncTime += second;
#endif
    if (!keySecurityChannel_->send(sslConnection_, (char*)sendHash, CHUNK_HASH_SIZE * batchNumber + 32)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }
    u_char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber + 32];
    int recvSize;
    if (!keySecurityChannel_->recv(sslConnection_, (char*)recvBuffer, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey_enc, NULL);
#endif
    u_char hmac[32];
    cryptoObj_->sha256Hmac(recvBuffer, CHUNK_HASH_SIZE * batchNumber, hmac, keyExchangeKey_, 32);
    if (memcmp(hmac, recvBuffer + batchNumber * CHUNK_HASH_SIZE, 32) != 0) {
        cerr << "KeyClient : recved keys hmac error" << endl;
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyClient : recv key exchange hmac = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, recvBuffer + CHUNK_HASH_SIZE * batchNumber, 32);
        cerr << "KeyClient : client computed key exchange hmac = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, hmac, 32);
#endif
        return false;
    }
    cryptoObj_->keyExchangeDecrypt(recvBuffer, batchkeyNumber * CHUNK_ENCRYPT_KEY_SIZE, keyExchangeKey_, keyExchangeKey_, batchKeyList);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKey_enc, NULL);
    diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    second = diff / 1000000.0;
    keyExchangeEncTime += second;
#endif
    return true;
}

bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection, CryptoPrimitive* cryptoObj)
{
    u_char sendHash[CHUNK_HASH_SIZE * batchNumber + 32];
    // #if SYSTEM_BREAK_DOWN == 1
    //     struct timeval timestartKey_enc;
    //     struct timeval timeendKey_enc;
    //     gettimeofday(&timestartKey_enc, NULL);
    // #endif
    cryptoObj->keyExchangeEncrypt(batchHashList, batchNumber * CHUNK_HASH_SIZE, keyExchangeKey_, keyExchangeKey_, sendHash);
    cryptoObj->sha256Hmac(sendHash, CHUNK_HASH_SIZE * batchNumber, sendHash + CHUNK_HASH_SIZE * batchNumber, keyExchangeKey_, 32);
#if SYSTEM_DEBUG_FLAG == 1
    cerr << "KeyClient : send key exchange hmac = " << endl;
    PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, sendHash + CHUNK_HASH_SIZE * batchNumber, 32);
#endif
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timeendKey_enc, NULL);
    //     long diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    //     double second = diff / 1000000.0;
    //     mutexkeyGenerateSimulatorEncTime_.lock();
    //     keyExchangeEncTime += second;
    //     mutexkeyGenerateSimulatorEncTime_.unlock();
    // #endif
    if (!securityChannel->send(sslConnection, (char*)sendHash, CHUNK_HASH_SIZE * batchNumber + 32)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }
    u_char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber + 32];
    int recvSize;
    if (!securityChannel->recv(sslConnection, (char*)recvBuffer, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timestartKey_enc, NULL);
    // #endif
    u_char hmac[32];
    cryptoObj->sha256Hmac(recvBuffer, CHUNK_HASH_SIZE * batchNumber, hmac, keyExchangeKey_, 32);
    if (memcmp(hmac, recvBuffer + batchNumber * CHUNK_HASH_SIZE, 32) != 0) {
        cerr << "KeyClient : recved keys hmac error" << endl;
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyClient : recv key exchange hmac = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, recvBuffer + CHUNK_HASH_SIZE * batchNumber, 32);
        cerr << "KeyClient : client computed key exchange hmac = " << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, hmac, 32);
#endif
        return false;
    }
    cryptoObj->keyExchangeDecrypt(recvBuffer, batchkeyNumber * CHUNK_ENCRYPT_KEY_SIZE, keyExchangeKey_, keyExchangeKey_, batchKeyList);
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timeendKey_enc, NULL);
    //     diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    //     second = diff / 1000000.0;
    //     mutexkeyGenerateSimulatorEncTime_.lock();
    //     keyExchangeEncTime += second;
    //     mutexkeyGenerateSimulatorEncTime_.unlock();
    // #endif
    return true;
}

#elif KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR

bool KeyClient::keyExchangeXOR(u_char* result, u_char* input, u_char* xorBase, int batchNumber)
{
    for (int i = 0; i < batchNumber * CHUNK_HASH_SIZE; i++) {
        result[i] = input[i] ^ xorBase[i];
    }
    return true;
}

bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, NetworkHeadStruct_t netHead)
{
    int sendSize = sizeof(NetworkHeadStruct_t) + CHUNK_HASH_SIZE * batchNumber + 32;
    u_char sendHash[sendSize];
    netHead.dataSize = batchNumber;
    memcpy(sendHash, &netHead, sizeof(NetworkHeadStruct_t));
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartKey_enc;
    struct timeval timeendKey_enc;
    long diff;
    double second;
    gettimeofday(&timestartKey_enc, NULL);
#endif
    u_char keyExchangeXORBase[batchNumber * CHUNK_HASH_SIZE * 2];
    cryptoObj_->keyExchangeCTRBaseGenerate(nonce_, counter_, batchNumber * 4, keyExchangeKey_, keyExchangeKey_, keyExchangeXORBase);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKey_enc, NULL);
    diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    second = diff / 1000000.0;
    keyExchangeMaskGenerateTime += second;
#endif
#if SYSTEM_DEBUG_FLAG == 1
    cerr << "key exchange mask = " << endl;
    PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, keyExchangeXORBase, batchNumber * CHUNK_HASH_SIZE * 2);
#endif
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey_enc, NULL);
#endif
    keyExchangeXOR(sendHash + sizeof(NetworkHeadStruct_t), batchHashList, keyExchangeXORBase, batchNumber);
    cryptoObj_->sha256Hmac(sendHash + sizeof(NetworkHeadStruct_t), CHUNK_HASH_SIZE * batchNumber, sendHash + sizeof(NetworkHeadStruct_t) + CHUNK_HASH_SIZE * batchNumber, keyExchangeKey_, 32);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKey_enc, NULL);
    diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    second = diff / 1000000.0;
    keyExchangeEncTime += second;
#endif
    if (!keySecurityChannel_->send(sslConnection_, (char*)sendHash, sendSize)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }
    u_char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber + 32];
    int recvSize;
    if (!keySecurityChannel_->recv(sslConnection_, (char*)recvBuffer, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKey_enc, NULL);
#endif
    u_char hmac[32];
    cryptoObj_->sha256Hmac(recvBuffer, CHUNK_HASH_SIZE * batchNumber, hmac, keyExchangeKey_, 32);
    if (memcmp(hmac, recvBuffer + batchNumber * CHUNK_HASH_SIZE, 32) != 0) {
        cerr << "KeyClient : recved keys hmac error" << endl;
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, hmac, 32);
        PRINT_BYTE_ARRAY_KEY_CLIENT(stderr, recvBuffer + batchNumber * CHUNK_HASH_SIZE, 32);
        return false;
    }
    keyExchangeXOR(batchKeyList, recvBuffer, keyExchangeXORBase + batchNumber * CHUNK_HASH_SIZE, batchNumber);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKey_enc, NULL);
    diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    second = diff / 1000000.0;
    keyExchangeEncTime += second;
#endif
    return true;
}

bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection, CryptoPrimitive* cryptoObj, u_char* nonce, uint32_t counter, NetworkHeadStruct_t netHead)
{
    int sendSize = sizeof(NetworkHeadStruct_t) + CHUNK_HASH_SIZE * batchNumber + 32;
    u_char sendHash[sendSize];
    netHead.dataSize = batchNumber;
    memcpy(sendHash, &netHead, sizeof(NetworkHeadStruct_t));
    // #if SYSTEM_BREAK_DOWN == 1
    //     struct timeval timestartKey_enc;
    //     struct timeval timeendKey_enc;
    //     long diff;
    //     double second;
    //     gettimeofday(&timestartKey_enc, NULL);
    // #endif
    u_char keyExchangeXORBase[batchNumber * CHUNK_HASH_SIZE * 2];
    cryptoObj->keyExchangeCTRBaseGenerate(nonce, counter, batchNumber * 4, keyExchangeKey_, keyExchangeKey_, keyExchangeXORBase);
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timeendKey_enc, NULL);
    //     diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    //     second = diff / 1000000.0;
    //     mutexkeyGenerateSimulatorEncTime_.lock();
    //     keyExchangeMaskGenerateTime += second;
    //     mutexkeyGenerateSimulatorEncTime_.unlock();
    // #endif
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timestartKey_enc, NULL);
    // #endif
    keyExchangeXOR(sendHash + sizeof(NetworkHeadStruct_t), batchHashList, keyExchangeXORBase, batchNumber);
    cryptoObj->sha256Hmac(sendHash + sizeof(NetworkHeadStruct_t), CHUNK_HASH_SIZE * batchNumber, sendHash + sizeof(NetworkHeadStruct_t) + CHUNK_HASH_SIZE * batchNumber, keyExchangeKey_, 32);
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timeendKey_enc, NULL);
    //     diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    //     second = diff / 1000000.0;
    //     mutexkeyGenerateSimulatorEncTime_.lock();
    //     keyExchangeEncTime += second;
    //     mutexkeyGenerateSimulatorEncTime_.unlock();
    // #endif
    if (!securityChannel->send(sslConnection, (char*)sendHash, sendSize)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }
    u_char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber + 32];
    int recvSize;
    if (!securityChannel->recv(sslConnection, (char*)recvBuffer, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timestartKey_enc, NULL);
    // #endif
    u_char hmac[32];
    cryptoObj->sha256Hmac(recvBuffer, CHUNK_HASH_SIZE * batchNumber, hmac, keyExchangeKey_, 32);
    if (memcmp(hmac, recvBuffer + batchNumber * CHUNK_HASH_SIZE, 32) != 0) {
        cerr << "KeyClient : recved keys hmac error" << endl;
        return false;
    }
    keyExchangeXOR(batchKeyList, recvBuffer, keyExchangeXORBase + batchNumber * CHUNK_HASH_SIZE, batchNumber);
    // #if SYSTEM_BREAK_DOWN == 1
    //     gettimeofday(&timeendKey_enc, NULL);
    //     diff = 1000000 * (timeendKey_enc.tv_sec - timestartKey_enc.tv_sec) + timeendKey_enc.tv_usec - timestartKey_enc.tv_usec;
    //     second = diff / 1000000.0;
    //     mutexkeyGenerateSimulatorEncTime_.lock();
    //     keyExchangeEncTime += second;
    //     mutexkeyGenerateSimulatorEncTime_.unlock();
    // #endif
    return true;
}
#endif

bool KeyClient::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool KeyClient::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool KeyClient::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}
