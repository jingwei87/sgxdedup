#ifndef SGXDEDUP_SENDER_HPP
#define SGXDEDUP_SENDER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "ssl.hpp"
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

class Sender {
private:
    std::mutex mutexSocket_;
    ssl* powSecurityChannel_;
    ssl* dataSecurityChannel_;
    SSL* sslConnectionPow_;
    SSL* sslConnectionData_;
    int clientID_;
    messageQueue<Data_t>* inputMQ_;
    CryptoPrimitive* cryptoObj_;

public:
    Sender();

    ~Sender();

    //status define in protocol.hpp
    bool sendRecipe(Recipe_t request, RecipeList_t requestList, int& status);
    bool sendChunkList(ChunkList_t request, int& status);
    bool sendChunkList(char* requestBufferIn, int sendBufferSize, int sendChunkNumber, int& status);
    bool getKeyServerSK(u_char* SK);
    //for pow
    bool sendSGXmsg01(uint32_t& msg0, sgx_ra_msg1_t& msg1, sgx_ra_msg2_t*& msg2, int& status);
    bool sendSGXmsg3(sgx_ra_msg3_t* msg3, uint32_t sz, ra_msg4_t*& msg4, int& status);
    bool sendEnclaveSignedHash(u_char* clientMac, u_char* hashList, int requestNumber, u_char* respond, int& status);
    bool sendLogOutMessage();
    bool sendLogInMessage(int loginType);
    //send chunk when socket free
    void run();

    //general send data
    bool sendDataPow(char* request, int requestSize, char* respond, int& respondSize);
    bool sendEndFlag();
    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool editJobDoneFlag();
};

#endif //SGXDEDUP_SENDER_HPP
