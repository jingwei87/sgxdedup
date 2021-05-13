#ifndef SGXDEDUP_CHUNK_HPP
#define SGXDEDUP_CHUNK_HPP

#include "configure.hpp"
#include <bits/stdc++.h>

using namespace std;

typedef struct {
    u_char hash[CHUNK_HASH_SIZE];
} Hash_t;
// system basic data structures
typedef struct {
    uint32_t ID;
    int type;
    int logicDataSize;
    u_char logicData[MAX_CHUNK_SIZE];
    u_char chunkHash[CHUNK_HASH_SIZE];
    u_char encryptKey[CHUNK_ENCRYPT_KEY_SIZE];
} Chunk_t;

typedef struct {
    int logicDataSize;
    char logicData[MAX_CHUNK_SIZE];
    char chunkHash[CHUNK_HASH_SIZE];
} StorageCoreData_t;

typedef struct {
    uint32_t ID;
    int logicDataSize;
    char logicData[MAX_CHUNK_SIZE];
} RetrieverData_t;

typedef struct {
    uint32_t chunkID;
    int chunkSize;
    u_char chunkHash[CHUNK_HASH_SIZE];
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE];
} RecipeEntry_t;

typedef vector<Chunk_t> ChunkList_t;
typedef vector<RecipeEntry_t> RecipeList_t;

typedef struct {
    uint64_t fileSize;
    u_char fileNameHash[FILE_NAME_HASH_SIZE];
    uint64_t totalChunkNumber;
} FileRecipeHead_t;

typedef struct {
    uint64_t fileSize;
    u_char fileNameHash[FILE_NAME_HASH_SIZE];
    uint64_t totalChunkKeyNumber;
} KeyRecipeHead_t;

typedef struct {
    FileRecipeHead_t fileRecipeHead;
    KeyRecipeHead_t keyRecipeHead;
} Recipe_t;

typedef struct {
    union {
        Chunk_t chunk;
        Recipe_t recipe;
    };
    int dataType;
} Data_t;

typedef struct {
    u_char originHash[CHUNK_HASH_SIZE];
    u_char key[CHUNK_ENCRYPT_KEY_SIZE];
} KeyGenEntry_t;

typedef struct {
    int fd;
    int epfd;
    u_char hashContent[CHUNK_HASH_SIZE * 3000];
    u_char keyContent[CHUNK_HASH_SIZE * 3000];
    int length = 0;
    int requestNumber = 0;
    bool keyGenerateFlag = false; // true - key gen done; false - key gen not start
    int clientID;
} KeyServerEpollMessage_t;

typedef struct {
    int messageType;
    int clientID;
    int dataSize;
} NetworkHeadStruct_t;

// database data structures

typedef struct {
    u_char containerName[16];
    uint32_t offset;
    uint32_t length;
} keyForChunkHashDB_t;

typedef struct {
    char RecipeFileName[FILE_NAME_HASH_SIZE];
    uint32_t version;
} keyForFilenameDB_t;

typedef struct {
    u_char hash_[CHUNK_HASH_SIZE];
} chunkHash_t;

#endif //SGXDEDUP_CHUNK_HPP
