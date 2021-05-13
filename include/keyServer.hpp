#ifndef SGXDEDUP_KEYSERVER_HPP
#define SGXDEDUP_KEYSERVER_HPP

#include "configure.hpp"
#include "dataStructure.hpp"
#include "kmClient.hpp"
#include "messageQueue.hpp"
#include "openssl/bn.h"
#include "ssl.hpp"
#include <bits/stdc++.h>
#define SERVERSIDE 0
#define CLIENTSIDE 1
#define KEYMANGER_PRIVATE_KEY "key/sslKeys/server-key.pem"

class keyServer {
private:
    RSA* rsa_;
    BIO* key_;
    const BIGNUM *keyN_, *keyD_;
    kmClient* client;
    std::mutex multiThreadMutex_;
    std::mutex multiThreadCountMutex_;
    std::mutex clientThreadNumberCountMutex_;
    uint64_t keyGenerateCount_;
    uint64_t clientThreadCount_;
    uint64_t sessionKeyRegressionMaxNumber_, sessionKeyRegressionCurrentNumber_;
    bool raRequestFlag_, raSetupFlag_, sessionKeyUpdateFlag_;
    std::mutex mutexSessionKeyUpdate;
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    bool offlineGenerateFlag_ = false;
#endif
    ssl* keySecurityChannel_;
public:
    keyServer(ssl* keySecurityChannelTemp);
    ~keyServer();
    bool runRemoteAttestationInit();
    void runRAwithSPRequest();
    void runSessionKeyUpdate();
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    void runCTRModeMaskGenerate();
#endif
    void runKeyGenerateThread(SSL* connection);
    bool initEnclaveViaRemoteAttestation(ssl* raSecurityChannel, SSL* sslConnection);
    bool getRASetupFlag();
};

#endif //SGXDEDUP_KEYSERVER_HPP
