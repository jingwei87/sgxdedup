#ifndef SGXDEDUP_RECIVER_HPP
#define SGXDEDUP_RECIVER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "ssl.hpp"
#include <bits/stdc++.h>

using namespace std;

class RecvDecode {
private:
    ssl* powSecurityChannel_;
    ssl* dataSecurityChannel_;
    SSL* sslConnectionPow_;
    SSL* sslConnectionData_;
    void receiveChunk();
    u_char fileNameHash_[FILE_NAME_HASH_SIZE];
    CryptoPrimitive* cryptoObj_;
    messageQueue<RetrieverData_t>* outPutMQ_;
    int clientID_;

public:
    Recipe_t fileRecipe_;
    RecvDecode(string fileName);
    ~RecvDecode();
    void run();
    bool recvFileHead(Recipe_t& FileRecipe, u_char* fileNameHash);
    RecipeList_t fileRecipeList_;
    bool processRecipe(Recipe_t& recipeHead, RecipeList_t& recipeList, u_char* fileNameHash);
    bool recvChunks(ChunkList_t& recvChunk, int& chunkNumber, uint32_t& startID, uint32_t& endID);
    Recipe_t getFileRecipeHead();
    bool insertMQ(RetrieverData_t& newChunk);
    bool extractMQ(RetrieverData_t& newChunk);
    bool getJobDoneFlag();
};

#endif //SGXDEDUP_RECIVER_HPP
