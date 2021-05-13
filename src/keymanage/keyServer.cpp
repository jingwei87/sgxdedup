#include "keyServer.hpp"
#include <fcntl.h>
#include <sys/time.h>
extern Configure config;

void PRINT_BYTE_ARRAY_KEY_SERVER(
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

keyServer::keyServer(ssl* keyServerSecurityChannelTemp)
{
    rsa_ = RSA_new();
    key_ = BIO_new_file(KEYMANGER_PRIVATE_KEY, "r");
    char passwd[5] = "1111";
    passwd[4] = '\0';
    PEM_read_bio_RSAPrivateKey(key_, &rsa_, NULL, passwd);
#if OPENSSL_V_1_0_2 == 1

    keyD_ = rsa_->d;
    keyN_ = rsa_->n;
#else
    RSA_get0_key(rsa_, &keyN_, nullptr, &keyD_);
#endif
    u_char keydBuffer[4096];
    int lenKeyd;
    lenKeyd = BN_bn2bin(keyD_, keydBuffer);
    string keyd((char*)keydBuffer, lenKeyd);
    sessionKeyRegressionMaxNumber_ = config.getKeyRegressionMaxTimes();
    client = new kmClient(keyd, sessionKeyRegressionMaxNumber_);
    sessionKeyRegressionCurrentNumber_ = sessionKeyRegressionMaxNumber_;
    clientThreadCount_ = 0;
    keyGenerateCount_ = 0;
    raRequestFlag_ = true;
    raSetupFlag_ = false;
    keySecurityChannel_ = keyServerSecurityChannelTemp;
}

keyServer::~keyServer()
{
    BIO_free_all(key_);
    RSA_free(rsa_);
    delete client;
    delete keySecurityChannel_;
}

bool keyServer::getRASetupFlag()
{
    return raSetupFlag_;
}

bool keyServer::initEnclaveViaRemoteAttestation(ssl* raSecurityChannel, SSL* sslConnection)
{
    if (!client->init(raSecurityChannel, sslConnection)) {
        cerr << "keyServer : enclave not truster" << endl;
        return false;
    } else {
        raSetupFlag_ = true;
        sessionKeyUpdateFlag_ = true;
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyServer : enclave trusted" << endl;
#endif
    }
    multiThreadCountMutex_.lock();
    keyGenerateCount_ = 0;
    multiThreadCountMutex_.unlock();
    return true;
}

void keyServer::runRAwithSPRequest()
{
    ssl* raSecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getkeyServerRArequestPort(), SERVERSIDE);
    char recvBuffer[sizeof(NetworkHeadStruct_t)];
    int recvSize;
    while (true) {
        SSL* sslConnection = raSecurityChannelTemp->sslListen().second;
        raSecurityChannelTemp->recv(sslConnection, recvBuffer, recvSize);
        raRequestFlag_ = true;
        cout << "KeyServer : recv storage server ra request, waiting for ra now" << endl;
        free(sslConnection);
        while (true) {
            while (!(clientThreadCount_ == 0))
                ;
            cout << "KeyServer : start do remote attestation to storage server, current time = " << endl;
            time_t timep;
            time(&timep);
            cout << asctime(gmtime(&timep));
            keyGenerateCount_ = 0;
            ssl* raSendSecurityChannelTemp = new ssl(config.getStorageServerIP(), config.getKMServerPort(), CLIENTSIDE);
            SSL* sslConnectionSend = raSendSecurityChannelTemp->sslConnect().second;
            int sendSize = sizeof(NetworkHeadStruct_t);
            char sendBuffer[sendSize];
            NetworkHeadStruct_t netHead;
            netHead.messageType = KEY_SERVER_RA_REQUES;
            netHead.dataSize = 0;
            memcpy(sendBuffer, &netHead, sizeof(NetworkHeadStruct_t));
            raSendSecurityChannelTemp->send(sslConnectionSend, sendBuffer, sendSize);
            bool remoteAttestationStatus = initEnclaveViaRemoteAttestation(raSendSecurityChannelTemp, sslConnectionSend);
            if (remoteAttestationStatus) {
                delete raSecurityChannelTemp;
                free(sslConnectionSend);
                raRequestFlag_ = false;
                cout << "KeyServer : do remote attestation to storage SP done, current time = " << endl;
                time_t timep;
                time(&timep);
                cout << asctime(gmtime(&timep));
                break;
            } else {
                delete raSecurityChannelTemp;
                free(sslConnectionSend);
                cerr << "KeyServer : do remote attestation to storage SP error" << endl;
                continue;
            }
        }
    }
}

bool keyServer::runRemoteAttestationInit()
{
    while (true) {
        cout << "KeyServer : start do remote attestation to storage server, current time = " << endl;
        time_t timep;
        time(&timep);
        cout << asctime(gmtime(&timep));
        keyGenerateCount_ = 0;
        ssl* raSecurityChannelTemp = new ssl(config.getStorageServerIP(), config.getKMServerPort(), CLIENTSIDE);
        SSL* sslConnection = raSecurityChannelTemp->sslConnect().second;
#if SYSTEM_DEBUG_FLAG == 1
        cout << "KeyServer : remote attestation thread connected storage server" << endl;
#endif
        int sendSize = sizeof(NetworkHeadStruct_t);
        char sendBuffer[sendSize];
        NetworkHeadStruct_t netHead;
        netHead.messageType = KEY_SERVER_RA_REQUES;
        netHead.dataSize = 0;
        memcpy(sendBuffer, &netHead, sizeof(NetworkHeadStruct_t));
        raSecurityChannelTemp->send(sslConnection, sendBuffer, sendSize);
        bool remoteAttestationStatus = initEnclaveViaRemoteAttestation(raSecurityChannelTemp, sslConnection);
        if (remoteAttestationStatus) {
            delete raSecurityChannelTemp;
            free(sslConnection);
            raRequestFlag_ = false;
            cout << "KeyServer : do remote attestation to storage SP done, current time = " << endl;
            time_t timep;
            time(&timep);
            cout << asctime(gmtime(&timep));
            break;
        } else {
            delete raSecurityChannelTemp;
            free(sslConnection);
            cerr << "KeyServer : do remote attestation to storage SP error" << endl;
            continue;
        }
    }
    return true;
}

void keyServer::runSessionKeyUpdate()
{
    struct timeval timestart;
    struct timeval timeend;
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
#endif
    while (true) {
        if (!sessionKeyUpdateFlag_) {
            continue;
        }
        mutexSessionKeyUpdate.lock();
        sessionKeyUpdateFlag_ = false;
        cout << "KeyServer : start keyServer session key update, current time = " << endl;
        time_t timep;
        time(&timep);
        cout << asctime(gmtime(&timep));
        while (true) {
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestart, 0);
#endif
            bool enclaveSessionKeyUpdateStatus = client->sessionKeyUpdate();
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeend, 0);
            diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
            second = diff / 1000000.0;
#endif
            if (enclaveSessionKeyUpdateStatus) {
                break;
            } else {
                cerr << "KeyServer : update session key error" << endl;
                continue;
            }
        }
        sessionKeyUpdateFlag_ = true;
        mutexSessionKeyUpdate.unlock();
        cerr << "KeyServer : keyServer session key update done, current regression counter = " << sessionKeyRegressionCurrentNumber_ << endl;
#if SYSTEM_BREAK_DOWN == 1
        cout << "KeyServer : session key counter = " << sessionKeyRegressionCurrentNumber_ << " update time = " << second << " s" << endl;
#endif
        sessionKeyRegressionCurrentNumber_--;
        boost::xtime xt;
        boost::xtime_get(&xt, boost::TIME_UTC_);
        xt.sec += config.getKeyRegressionIntervals();
        boost::thread::sleep(xt);
    }
    return;
}

#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CFB

void keyServer::runKeyGenerateThread(SSL* connection)
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestart;
    struct timeval timeend;
    double keyGenTime = 0;
    long diff;
    double second;
#endif
    multiThreadCountMutex_.lock();
    clientThreadCount_++;
    multiThreadCountMutex_.unlock();
    uint64_t currentThreadkeyGenerationNumber = 0;
    while (true) {
        u_char hash[config.getKeyBatchSize() * CHUNK_HASH_SIZE + 32];
        int recvSize = 0;
        if (!keySecurityChannel_->recv(connection, (char*)hash, recvSize)) {
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
#endif
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
            multiThreadCountMutex_.unlock();
            return;
        }

        int recvNumber = (recvSize - 32) / CHUNK_HASH_SIZE;
        if (recvNumber == 0) {
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
#endif
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
            multiThreadCountMutex_.unlock();
            return;
        }
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "KeyServer : recv hash number = " << recvNumber << ", recv size = " << recvSize << endl;
        cerr << "KeyServer : recved hmac = " << endl;
        PRINT_BYTE_ARRAY_KEY_SERVER(stderr, hash + recvNumber * CHUNK_HASH_SIZE, 32);
#endif
        u_char key[recvSize];
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestart, 0);
#endif
        client->request(hash, recvSize, key, recvSize);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeend, 0);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        keyGenTime += second;
#endif
        multiThreadMutex_.lock();
        keyGenerateCount_ += recvNumber;
        multiThreadMutex_.unlock();
        currentThreadkeyGenerationNumber += recvNumber;
        if (!keySecurityChannel_->send(connection, (char*)key, recvSize)) {
            cerr << "KeyServer : error send back chunk key to client" << endl;
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
#endif
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
            multiThreadCountMutex_.unlock();
            return;
        }
    }
}

#elif KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR

void keyServer::runCTRModeMaskGenerate()
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestart;
    struct timeval timeend;
    long diff;
    double second;
#endif
    while (true) {
        boost::xtime xt;
        boost::xtime_get(&xt, boost::TIME_UTC_);
        xt.sec = 5;
        boost::thread::sleep(xt);
        if (raRequestFlag_ == false && offlineGenerateFlag_ == true && clientThreadCount_ == 0) {
            multiThreadCountMutex_.lock();
            mutexSessionKeyUpdate.lock();
            cerr << "KeyServer : start offlien mask generate" << endl;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestart, 0);
#endif
            client->maskGenerate();
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeend, 0);
            diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
            second = diff / 1000000.0;
            cout << "KeyServer : offline mask generate time = " << second << " s" << endl;
#endif
            offlineGenerateFlag_ = false;
            cerr << "KeyServer : offlien mask generate done" << endl;
            mutexSessionKeyUpdate.unlock();
            multiThreadCountMutex_.unlock();
        }
    }
}

void keyServer::runKeyGenerateThread(SSL* connection)
{
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestart;
    struct timeval timeend;
    double keyGenTime = 0;
    long diff;
    double second;
#endif
    multiThreadCountMutex_.lock();
    clientThreadCount_++;
    offlineGenerateFlag_ = false;
    multiThreadCountMutex_.unlock();
    int recvSize = 0;
    uint64_t currentThreadkeyGenerationNumber = 0;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestart, 0);
#endif
    cerr << "KeyServer : start recv init messages" << endl;
    NetworkHeadStruct_t netHead;
    char initInfoBuffer[48 + sizeof(NetworkHeadStruct_t)]; // clientID & nonce & counter
    while (true) {
        if (keySecurityChannel_->recv(connection, initInfoBuffer, recvSize)) {
            memcpy(&netHead, initInfoBuffer, sizeof(NetworkHeadStruct_t));
            u_char cipherBuffer[16], hmacbuffer[32];
            memcpy(cipherBuffer, initInfoBuffer + sizeof(NetworkHeadStruct_t), 16);
            memcpy(hmacbuffer, initInfoBuffer + sizeof(NetworkHeadStruct_t) + 16, 32);
            multiThreadMutex_.lock();
#if SYSTEM_DEBUG_FLAG == 1
            cout << "KeyServer : modify client info for client = " << netHead.clientID << endl;
#endif
            int modifyClientInfoStatus = client->modifyClientStatus(netHead.clientID, cipherBuffer, hmacbuffer);
#if SYSTEM_DEBUG_FLAG == 1
            cout << "KeyServer : modify client info done for client = " << netHead.clientID << endl;
#endif
            multiThreadMutex_.unlock();
            if (modifyClientInfoStatus == SUCCESS || modifyClientInfoStatus == CLIENT_COUNTER_REST) {
                char responseBuffer[sizeof(NetworkHeadStruct_t)];
                NetworkHeadStruct_t responseHead;
                responseHead.clientID = netHead.clientID;
                responseHead.dataSize = 0;
                responseHead.messageType = modifyClientInfoStatus;
                int sendSize = sizeof(NetworkHeadStruct_t);
                memcpy(responseBuffer, &responseHead, sizeof(NetworkHeadStruct_t));
                keySecurityChannel_->send(connection, responseBuffer, sendSize);
                break;
            } else if (modifyClientInfoStatus == ERROR_RESEND || modifyClientInfoStatus == NONCE_HAS_USED) {
                char responseBuffer[sizeof(NetworkHeadStruct_t)];
                NetworkHeadStruct_t responseHead;
                responseHead.clientID = netHead.clientID;
                responseHead.dataSize = 0;
                responseHead.messageType = modifyClientInfoStatus;
                int sendSize = sizeof(NetworkHeadStruct_t);
                memcpy(responseBuffer, &responseHead, sizeof(NetworkHeadStruct_t));
                keySecurityChannel_->send(connection, responseBuffer, sendSize);
            } else if (modifyClientInfoStatus == -1) {
                cerr << "KeyServer : error init client messages, ecall not correct" << endl;
                return;
            }
        } else {
            cerr << "KeyServer : error recv client init messages" << endl;
            return;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeend, 0);
    diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    second = diff / 1000000.0;
    cout << "KeyServer : setup client init messages time = " << second << " s" << endl;
#endif
    //done
    while (true) {
        u_char hash[sizeof(NetworkHeadStruct_t) + config.getKeyBatchSize() * CHUNK_HASH_SIZE + 32];
        if (!keySecurityChannel_->recv(connection, (char*)hash, recvSize)) {

            multiThreadCountMutex_.lock();
            clientThreadCount_--;
            offlineGenerateFlag_ = true;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
#endif
            multiThreadCountMutex_.unlock();
            return;
        }
        memcpy(&netHead, hash, sizeof(NetworkHeadStruct_t));
        int recvNumber = netHead.dataSize;
#if SYSTEM_DEBUG_FLAG == 1
        cout << "KeyServer : recv hash number = " << recvNumber << endl;
#endif
        u_char key[netHead.dataSize * CHUNK_HASH_SIZE + 32];
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestart, 0);
#endif
        client->request(hash + sizeof(NetworkHeadStruct_t), netHead.dataSize * CHUNK_HASH_SIZE + 32, key, netHead.dataSize * CHUNK_HASH_SIZE + 32, netHead.clientID);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeend, 0);
        diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
        second = diff / 1000000.0;
        keyGenTime += second;
#endif
#if SYSTEM_DEBUG_FLAG == 1
        cout << "KeyServer : generate key done for hash number = " << recvNumber << endl;
#endif
        multiThreadMutex_.lock();
        keyGenerateCount_ += recvNumber;
        multiThreadMutex_.unlock();
        currentThreadkeyGenerationNumber += recvNumber;
        if (!keySecurityChannel_->send(connection, (char*)key, recvNumber * CHUNK_ENCRYPT_KEY_SIZE + 32)) {
            cerr << "KeyServer : error send back chunk key to client" << endl;
            multiThreadCountMutex_.lock();
            clientThreadCount_--;
#if SYSTEM_BREAK_DOWN == 1
            cout << "KeyServer : total key generation time = " << keyGenTime << " s" << endl;
            cout << "KeyServer : total key generation number = " << currentThreadkeyGenerationNumber << endl;
            cerr << "keyServer : Thread exit due to client disconnect， current client counter = " << clientThreadCount_ << endl;
#endif
            multiThreadCountMutex_.unlock();
            return;
        }
#if SYSTEM_DEBUG_FLAG == 1
        else {
            cout << "KeyServer : send key to client " << netHead.clientID << " done for hash number = " << recvNumber << endl;
        }
#endif
    }
}

#endif
