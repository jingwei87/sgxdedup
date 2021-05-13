#include "storageCore.hpp"
#include <sys/time.h>

struct timeval timestartStorage;
struct timeval timeendStorage;

extern Configure config;
extern Database fp2ChunkDB;
extern Database fileName2metaDB;

void PRINT_BYTE_ARRAY_STORAGE_CORE(
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

StorageCore::StorageCore()
{
    RecipeNamePrefix_ = config.getRecipeRootPath();
    containerNamePrefix_ = config.getContainerRootPath();
    maxContainerSize_ = config.getMaxContainerSize();
    RecipeNameTail_ = ".recipe";
    containerNameTail_ = ".container";
    ifstream fin;
    fin.open(".StorageConfig", ifstream::in);
    if (fin.is_open()) {
        fin >> lastContainerFileName_;
        fin >> currentContainer_.used_;
        fin.close();
        cerr << "StorageCore : read old storage configure, last container name = " << lastContainerFileName_ << ", used size = " << currentContainer_.used_ << endl;
        //read last container
        fin.open(containerNamePrefix_ + lastContainerFileName_ + containerNameTail_, ifstream::in | ifstream::binary);
        fin.read(currentContainer_.body_, currentContainer_.used_);
        fin.close();

    } else {
        lastContainerFileName_ = "abcdefghijklmno";
        currentContainer_.used_ = 0;
    }
    cryptoObj_ = new CryptoPrimitive();
}

StorageCore::~StorageCore()
{
    ofstream fout;
    fout.open(".StorageConfig", ofstream::out);
    fout << lastContainerFileName_ << endl;
    fout << currentContainer_.used_ << endl;
    fout.close();

    string writeContainerName = containerNamePrefix_ + lastContainerFileName_ + containerNameTail_;
    currentContainer_.saveTOFile(writeContainerName);

    delete cryptoObj_;
}

#if SYSTEM_BREAK_DOWN == 1
// type true == upload, false == download
bool StorageCore::clientExitSystemStatusOutput(bool type)
{
    cout << "StorageCore : service for client done, output service status:" << endl;
    if (type == true) {
        cout << "StorageCore : store chunk insert database time = " << storeChunkInsertDBTime << " s" << endl;
        cout << "StorageCore : store chunk write container time = " << writeContainerTime << " s" << endl;
        cout << "StorageCore : unique chunk number = " << uniqueChunkNumber << ", DB size = " << fp2ChunkDB.getDBSize() << endl;
        storeChunkInsertDBTime = 0;
        writeContainerTime = 0;
        uniqueChunkNumber = 0;
    } else {
        cout << "StorageCore : restore chunk query database time = " << restoreChunkQueryDBTime << " s" << endl;
        cout << "StorageCore : restore chunk read container time = " << readContainerTime << " s" << endl;
        cout << "StorageCore : restore chunk read container number = " << readContainerNumber << endl;
#if TRACE_DRIVEN_TEST == 1
        cout << "StorageCore : trace not found chunk number = " << notFoundChunkNumber << endl;
        notFoundChunkNumber = 0;
#endif
        restoreChunkQueryDBTime = 0;
        readContainerTime = 0;
        readContainerNumber = 0;
    }
    return true;
}
#endif

bool StorageCore::storeChunks(NetworkHeadStruct_t& networkHead, char* data)
{
    // gettimeofday(&timestartStorage, NULL);
    int chunkNumber;
    memcpy(&chunkNumber, data, sizeof(int));
    int readSize = sizeof(int);
    string tmpdata;
    for (int i = 0; i < chunkNumber; i++) {
        int currentChunkSize;
        string originHash(data + readSize, CHUNK_HASH_SIZE);
        readSize += CHUNK_HASH_SIZE;
        memcpy(&currentChunkSize, data + readSize, sizeof(int));
        readSize += sizeof(int);
        if (!storeChunk(originHash, data + readSize, currentChunkSize)) {
            return false;
        }
        readSize += currentChunkSize;
    }

    return true;
}

bool StorageCore::restoreRecipesSize(char* fileNameHash, uint64_t& recipeSize)
{
    string recipeName;
    string DBKey(fileNameHash, FILE_NAME_HASH_SIZE);
    if (fileName2metaDB.query(DBKey, recipeName)) {
        ifstream RecipeIn;
        string readRecipeName;
        readRecipeName = RecipeNamePrefix_ + recipeName + RecipeNameTail_;
        RecipeIn.open(readRecipeName, ifstream::in | ifstream::binary);
        if (!RecipeIn.is_open()) {
            cerr << "StorageCore : Can not open Recipe file, name =  " << readRecipeName;
            return false;
        } else {
            RecipeIn.seekg(0, std::ios::end);
            recipeSize = RecipeIn.tellg();
            RecipeIn.seekg(0, std::ios::beg);
            RecipeIn.close();
            return true;
        }
    } else {
        cerr << "StorageCore : file recipe not exist" << endl;
        return false;
    }
    return true;
}

bool StorageCore::restoreRecipes(char* fileNameHash, u_char* recipeContent, uint64_t& recipeSize)
{
    string recipeName;
    string DBKey(fileNameHash, FILE_NAME_HASH_SIZE);
    if (fileName2metaDB.query(DBKey, recipeName)) {
        ifstream RecipeIn;
        string readRecipeName;

        readRecipeName = RecipeNamePrefix_ + recipeName + RecipeNameTail_;
        RecipeIn.open(readRecipeName, ifstream::in | ifstream::binary);
        if (!RecipeIn.is_open()) {
            cerr << "StorageCore : Can not open Recipe file, name =  " << readRecipeName;
            return false;
        } else {
            RecipeIn.seekg(0, std::ios::end);
            recipeSize = RecipeIn.tellg();
            RecipeIn.seekg(0, std::ios::beg);
            RecipeIn.read((char*)recipeContent, recipeSize);
            RecipeIn.close();
            return true;
        }
    } else {
        cerr << "StorageCore : file recipe not exist" << endl;
        return false;
    }
    return true;
}

bool StorageCore::storeRecipes(char* fileNameHash, u_char* recipeContent, uint64_t recipeSize)
{

    ofstream RecipeOut;
    string writeRecipeName, buffer, recipeName;
#if MULTI_CLIENT_UPLOAD_TEST == 1
    mutexContainerOperation_.lock();
#endif
    string DBKey(fileNameHash, FILE_NAME_HASH_SIZE);
    if (fileName2metaDB.query(DBKey, recipeName)) {
        cerr << "StorageCore : current file's recipe exist, modify it now, recipe name = \n\t"
             << recipeName << endl;
        writeRecipeName = RecipeNamePrefix_ + recipeName + RecipeNameTail_;
        RecipeOut.open(writeRecipeName, ios::app | ios::binary);
        if (!RecipeOut.is_open()) {
            cerr << "StorageCore : Can not open Recipe file, name =  " << writeRecipeName << endl;
#if MULTI_CLIENT_UPLOAD_TEST == 1
            mutexContainerOperation_.unlock();
#endif
            return false;
        }
        RecipeOut.write((char*)recipeContent, recipeSize);
        RecipeOut.close();
#if MULTI_CLIENT_UPLOAD_TEST == 1
        mutexContainerOperation_.unlock();
#endif
        return true;
    } else {
        char recipeNameBuffer[FILE_NAME_HASH_SIZE * 2 + 1];
        for (int i = 0; i < FILE_NAME_HASH_SIZE; i++) {
            sprintf(recipeNameBuffer + 2 * i, "%02X", fileNameHash[i]);
        }
        cerr << "StorageCore : current file's recipe not exist, new recipe file name = \n\t"
             << recipeNameBuffer << endl;
        string recipeNameNew(recipeNameBuffer, FILE_NAME_HASH_SIZE * 2);
        fileName2metaDB.insert(DBKey, recipeNameNew);
        writeRecipeName = RecipeNamePrefix_ + recipeNameNew + RecipeNameTail_;
        RecipeOut.open(writeRecipeName, ios::app | ios::binary);
        if (!RecipeOut.is_open()) {
            cerr << "StorageCore : Can not open Recipe file, name =  " << writeRecipeName << endl;
#if MULTI_CLIENT_UPLOAD_TEST == 1
            mutexContainerOperation_.unlock();
#endif
            return false;
        }
        RecipeOut.write((char*)recipeContent, recipeSize);
        RecipeOut.close();
#if MULTI_CLIENT_UPLOAD_TEST == 1
        mutexContainerOperation_.unlock();
#endif
        return true;
    }
}

bool StorageCore::restoreRecipeAndChunk(char* recipeList, uint32_t startID, uint32_t endID, char* restoredChunkList, int& restoredChunkNumber, int& restoredChunkSize)
{
    int index = 0;
    restoredChunkNumber = endID - startID;
    for (int i = 0; i < restoredChunkNumber; i++) {
        int chunkSize = 0;
        memcpy(&chunkSize, recipeList + i * (CHUNK_HASH_SIZE + sizeof(int)), sizeof(int));
        string chunkHash(recipeList + i * (CHUNK_HASH_SIZE + sizeof(int)) + sizeof(int), CHUNK_HASH_SIZE);
        // cout << "Restore chunk ID = " << startID + i << ", chunk size = " << chunkSize << endl;
        string chunkData;
        if (restoreChunk(chunkHash, chunkData)) {
            if (chunkData.length() != chunkSize) {
                cerr << "StorageCore : restore chunk logic data size error for chunk " << startID + i << " , chunk size = " << chunkSize << " chunk hash = " << endl;
                PRINT_BYTE_ARRAY_STORAGE_CORE(stderr, &chunkHash[0], CHUNK_HASH_SIZE);
                return false;
            } else {
                uint32_t chunkID = startID + i;
                memcpy(restoredChunkList + index, &chunkID, sizeof(uint32_t));
                index += sizeof(uint32_t);
                memcpy(restoredChunkList + index, &chunkSize, sizeof(int));
                index += sizeof(int);
                memcpy(restoredChunkList + index, &chunkData[0], chunkSize);
                index += chunkSize;
                restoredChunkSize += chunkSize;
            }
        } else {
#if TRACE_DRIVEN_TEST == 1
            uint32_t chunkID = startID + i;
            memcpy(restoredChunkList + index, &chunkID, sizeof(uint32_t));
            index += sizeof(uint32_t);
            memcpy(restoredChunkList + index, &chunkSize, sizeof(int));
            index += sizeof(int);
            memset(restoredChunkList + index, 0, chunkSize);
            index += chunkSize;
            notFoundChunkNumber++;
            restoredChunkSize += chunkSize;
#else
            cerr << "StorageCore : can not restore chunk " << startID + i << " , chunk size = " << chunkSize << " chunk hash = " << endl;
            PRINT_BYTE_ARRAY_STORAGE_CORE(stderr, &chunkHash[0], CHUNK_HASH_SIZE);
            return false;
#endif
        }
    }
    return true;
}

bool StorageCore::storeChunk(std::string chunkHash, char* chunkData, int chunkSize)
{
    keyForChunkHashDB_t key;
    key.length = chunkSize;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartStorage, NULL);
#endif
    bool status = writeContainer(key, chunkData);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendStorage, NULL);
    writeContainerTime += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
    if (!status) {
        cerr << "StorageCore : Error write container" << endl;
        return status;
    }

#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartStorage, NULL);
#endif
    string dbValue;
    dbValue.resize(sizeof(keyForChunkHashDB_t));
    memcpy(&dbValue[0], &key, sizeof(keyForChunkHashDB_t));
    if (chunkHash.size() != CHUNK_HASH_SIZE) {
        cout << "error insert chunk hash" << endl;
        PRINT_BYTE_ARRAY_STORAGE_CORE(stdout, &chunkHash[0], chunkHash.size());
    }
    status = fp2ChunkDB.insert(chunkHash, dbValue);
    uniqueChunkNumber++;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendStorage, NULL);
    storeChunkInsertDBTime += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
    if (!status) {
        cerr << "StorageCore : Can't insert chunk to database" << endl;
        return false;
    } else {
        currentContainer_.used_ += key.length;
        return true;
    }
}

bool StorageCore::restoreChunk(std::string chunkHash, std::string& chunkDataStr)
{
    keyForChunkHashDB_t key;
    string ans;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartStorage, NULL);
#endif
    bool status = fp2ChunkDB.query(chunkHash, ans);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendStorage, NULL);
    int diff = 1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec;
    double second = diff / 1000000.0;
    restoreChunkQueryDBTime += second;
#endif
    if (status) {
        memcpy(&key, &ans[0], sizeof(keyForChunkHashDB_t));
        char chunkData[key.length];
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartStorage, NULL);
#endif

        bool readContainerStatus = readContainer(key, chunkData);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendStorage, NULL);
        readContainerTime += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
        if (readContainerStatus) {
            chunkDataStr.resize(key.length);
            memcpy(&chunkDataStr[0], chunkData, key.length);
            return true;
        } else {
            cerr << "StorageCore : can not read container for chunk" << endl;
            return false;
        }
    } else {
        // cerr << "StorageCore : chunk not in database" << endl;
        return false;
    }
}

bool StorageCore::writeContainer(keyForChunkHashDB_t& key, char* data)
{
#if MULTI_CLIENT_UPLOAD_TEST == 1
    mutexContainerOperation_.lock();
#endif
    if (key.length + currentContainer_.used_ < maxContainerSize_) {
        memcpy(&currentContainer_.body_[currentContainer_.used_], data, key.length);
        memcpy(key.containerName, &lastContainerFileName_[0], lastContainerFileName_.length());
    } else {
        string writeContainerName = containerNamePrefix_ + lastContainerFileName_ + containerNameTail_;
        currentContainer_.saveTOFile(writeContainerName);
        next_permutation(lastContainerFileName_.begin(), lastContainerFileName_.end());
        currentContainer_.used_ = 0;
        memcpy(&currentContainer_.body_[currentContainer_.used_], data, key.length);
        memcpy(key.containerName, &lastContainerFileName_[0], lastContainerFileName_.length());
    }
    key.offset = currentContainer_.used_;
#if MULTI_CLIENT_UPLOAD_TEST == 1
    mutexContainerOperation_.unlock();
#endif
    return true;
}

bool StorageCore::readContainer(keyForChunkHashDB_t key, char* data)
{
    ifstream containerIn;
    string containerNameStr((char*)key.containerName, lastContainerFileName_.length());
    string readName = containerNamePrefix_ + containerNameStr + containerNameTail_;
    if (containerNameStr.compare(lastContainerFileName_) == 0) {
        memcpy(data, currentContainer_.body_ + key.offset, key.length);
        return true;
    } else {
#if STORAGE_CORE_READ_CACHE == 1
        bool cacheHitStatus = containerCache.existsInCache(containerNameStr);
        if (cacheHitStatus) {
            string containerDataStr = containerCache.getFromCache(containerNameStr);
            memcpy(data, &containerDataStr[0] + key.offset, key.length);
            return true;
        } else {
            containerIn.open(readName, std::ifstream::in | std::ifstream::binary);
            if (!containerIn.is_open()) {
                cerr << "StorageCore : Can not open Container: " << readName << endl;
                return false;
            }
            containerIn.seekg(0, ios_base::end);
            int containerSize = containerIn.tellg();
            containerIn.seekg(0, ios_base::beg);
            containerIn.read(currentReadContainer_.body_, containerSize);
            containerIn.close();
            if (containerIn.gcount() != containerSize) {
                cerr << "StorageCore : read container " << readName << " error, should read " << containerSize << ", read in size " << containerIn.gcount() << endl;
                return false;
            }
            memcpy(data, currentReadContainer_.body_ + key.offset, key.length);
            string containerDataStrTemp(currentReadContainer_.body_, containerSize);
            containerCache.insertToCache(containerNameStr, containerDataStrTemp);
            return true;
        }
#else
        if (currentReadContainerFileName_.compare(containerNameStr) == 0) {
            memcpy(data, currentReadContainer_.body_ + key.offset, key.length);
            return true;
        } else {
            containerIn.open(readName, std::ifstream::in | std::ifstream::binary);
            if (!containerIn.is_open()) {
                cerr << "StorageCore : Can not open Container, name = " << readName << endl;
                return false;
            }
            containerIn.seekg(0, ios_base::end);
            int containerSize = containerIn.tellg();
            containerIn.seekg(0, ios_base::beg);
            containerIn.read(currentReadContainer_.body_, containerSize);
            containerIn.close();
            if (containerIn.gcount() != containerSize) {
                cerr << "StorageCore : read container " << readName << " error, should read " << containerSize << ", read in size " << containerIn.gcount() << endl;
                return false;
            }
            memcpy(data, currentReadContainer_.body_ + key.offset, key.length);
            currentReadContainerFileName_ = containerNameStr;
            readContainerNumber++;
            return true;
        }
#endif
    }
}

bool Container::saveTOFile(string fileName)
{
    ofstream containerOut;
    containerOut.open(fileName, std::ofstream::out | std::ofstream::binary);
    if (!containerOut.is_open()) {
        cerr << "ContainerManager : Can not open Container file : " << fileName << endl;
        return false;
    }
#if MULTI_CLIENT_UPLOAD_TEST == 0
    containerOut.write(this->body_, this->used_);
#endif
    cerr << "ContainerManager : save " << setbase(10) << this->used_ << " bytes to file system" << endl;
    containerOut.close();
    return true;
}