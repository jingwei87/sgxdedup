#ifndef SGXDEDUP_STORAGECORE_HPP
#define SGXDEDUP_STORAGECORE_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "database.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include <bits/stdc++.h>

using namespace std;

class Container {
public:
    uint32_t used_ = 0;
    char body_[2 << 23]; //8 M container size
    Container() { }
    ~Container() { }
    bool saveTOFile(string fileName);
};

class StorageCore {
private:
    std::string lastContainerFileName_;
    std::string currentReadContainerFileName_;
    std::string containerNamePrefix_;
    std::string containerNameTail_;
    std::string RecipeNamePrefix_;
    std::string RecipeNameTail_;
    CryptoPrimitive* cryptoObj_;
    Container currentContainer_;
    Container currentReadContainer_;
    uint64_t maxContainerSize_;
    bool writeContainer(keyForChunkHashDB_t& key, char* data);
    bool readContainer(keyForChunkHashDB_t key, char* data);
#if SYSTEM_BREAK_DOWN == 1
    double storeChunkInsertDBTime = 0;
    double restoreChunkQueryDBTime = 0;
    double readContainerTime = 0;
    double writeContainerTime = 0;
#endif
    int readContainerNumber = 0;
    uint64_t uniqueChunkNumber = 0;
#if TRACE_DRIVEN_TEST == 1
    uint64_t notFoundChunkNumber = 0;
#endif

#if MULTI_CLIENT_UPLOAD_TEST == 1
    std::mutex mutexContainerOperation_;
#endif
public:
    StorageCore();
    ~StorageCore();
    bool restoreChunks(NetworkHeadStruct_t& networkHead, char* data);
    bool storeRecipes(char* fileNameHash, u_char* recipeContent, uint64_t recipeSize);
    bool restoreRecipeAndChunk(char* recipeList, uint32_t startID, uint32_t endID, char* restoredChunkList, int& restoredChunkNumber, int& restoredChunkSize);
    bool storeChunk(string chunkHash, char* chunkData, int chunkSize);
    bool storeChunks(NetworkHeadStruct_t& networkHead, char* data);
    bool restoreChunk(std::string chunkHash, std::string& chunkDataStr);
    bool restoreRecipes(char* fileNameHash, u_char* recipeContent, uint64_t& recipeSize);
    bool restoreRecipesSize(char* fileNameHash, uint64_t& recipeSize);
#if SYSTEM_BREAK_DOWN == 1
    bool clientExitSystemStatusOutput(bool type); // type true == upload, false == download
#endif
};

#endif //SGXDEDUP_STORAGECORE_HPP