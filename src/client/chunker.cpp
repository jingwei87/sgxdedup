#include "chunker.hpp"
#include "sys/time.h"
extern Configure config;

struct timeval timestartChunker;
struct timeval timeendChunker;
struct timeval timestartChunkerInsertMQ;
struct timeval timeendChunkerInsertMQ;
struct timeval timestartChunkerReadFile;
struct timeval timeendChunkerReadFile;

void PRINT_BYTE_ARRAY_CHUNKER(
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

Chunker::Chunker(std::string path, Fingerprinter* FingerprinterObjTemp)
{
    loadChunkFile(path);
    ChunkerInit(path);
    cryptoObj_ = new CryptoPrimitive();
    FingerprinterObj_ = FingerprinterObjTemp;
}

Chunker::~Chunker()
{
    if (powerLUT_ != NULL) {
        delete powerLUT_;
    }
    if (removeLUT_ != NULL) {
        delete removeLUT_;
    }
    if (waitingForChunkingBuffer_ != NULL) {
        delete waitingForChunkingBuffer_;
    }
    if (chunkBuffer_ != NULL) {
        delete chunkBuffer_;
    }
    if (cryptoObj_ != NULL) {
        delete cryptoObj_;
    }
    if (chunkingFile_.is_open()) {
        chunkingFile_.seekg(0, ios::beg);
        chunkingFile_.close();
    }
}

std::ifstream& Chunker::getChunkingFile()
{
    if (!chunkingFile_.is_open()) {
        cerr << "Chunker : chunking file open failed" << endl;
        exit(1);
    } else {
        chunkingFile_.seekg(0, ios::beg);
    }
    return chunkingFile_;
}

void Chunker::loadChunkFile(std::string path)
{
    if (chunkingFile_.is_open()) {
        chunkingFile_.close();
    }
    chunkingFile_.open(path, std::ios::binary);
    if (!chunkingFile_.is_open()) {
        cerr << "Chunker : open file: " << path << "error, client exit now" << endl;
        exit(1);
    }
}

void Chunker::ChunkerInit(string path)
{
    u_char filePathHash[FILE_NAME_HASH_SIZE];
    cryptoObj_->generateHash((u_char*)&path[0], path.length(), filePathHash);
    memcpy(fileRecipe_.recipe.fileRecipeHead.fileNameHash, filePathHash, FILE_NAME_HASH_SIZE);
    memcpy(fileRecipe_.recipe.keyRecipeHead.fileNameHash, filePathHash, FILE_NAME_HASH_SIZE);

    ChunkerType_ = (int)config.getChunkingType();

    if (ChunkerType_ == CHUNKER_VAR_SIZE_TYPE) {
        int numOfMaskBits_;
        avgChunkSize_ = (int)config.getAverageChunkSize();
        minChunkSize_ = (int)config.getMinChunkSize();
        maxChunkSize_ = (int)config.getMaxChunkSize();
        slidingWinSize_ = (int)config.getSlidingWinSize();
        ReadSize_ = config.getReadSize();
        ReadSize_ = ReadSize_ * 1024 * 1024;
        waitingForChunkingBuffer_ = new u_char[ReadSize_];
        chunkBuffer_ = new u_char[maxChunkSize_];
        memset(waitingForChunkingBuffer_, 0, ReadSize_);
        memset(chunkBuffer_, 0, maxChunkSize_);

        if (waitingForChunkingBuffer_ == NULL || chunkBuffer_ == NULL) {
            cerr << "Chunker : Memory malloc error" << endl;
            exit(1);
        }
        if (minChunkSize_ >= avgChunkSize_) {
            cerr << "Chunker : minChunkSize_ should be smaller than avgChunkSize_!" << endl;
            exit(1);
        }
        if (maxChunkSize_ <= avgChunkSize_) {
            cerr << "Chunker : maxChunkSize_ should be larger than avgChunkSize_!" << endl;
            exit(1);
        }

        /*initialize the base and modulus for calculating the fingerprint of a window*/
        /*these two values were employed in open-vcdiff: "http://code.google.com/p/open-vcdiff/"*/
        polyBase_ = 257; /*a prime larger than 255, the max value of "unsigned char"*/
        polyMOD_ = (1 << 23) - 1; /*polyMOD_ - 1 = 0x7fffff: use the last 23 bits of a polynomial as its hash*/
        /*initialize the lookup table for accelerating the power calculation in rolling hash*/
        powerLUT_ = (uint32_t*)malloc(sizeof(uint32_t) * slidingWinSize_);
        memset(powerLUT_, 0, sizeof(uint32_t) * slidingWinSize_);
        /*powerLUT_[i] = power(polyBase_, i) mod polyMOD_*/
        powerLUT_[0] = 1;
        for (int i = 1; i < slidingWinSize_; i++) {
            /*powerLUT_[i] = (powerLUT_[i-1] * polyBase_) mod polyMOD_*/
            powerLUT_[i] = (powerLUT_[i - 1] * polyBase_) & polyMOD_;
        }
        /*initialize the lookup table for accelerating the byte remove in rolling hash*/
        removeLUT_ = (uint32_t*)malloc(sizeof(uint32_t) * 256); /*256 for unsigned char*/
        memset(removeLUT_, 0, sizeof(uint32_t) * 256);
        for (int i = 0; i < 256; i++) {
            /*removeLUT_[i] = (- i * powerLUT_[_slidingWinSize-1]) mod polyMOD_*/
            removeLUT_[i] = (i * powerLUT_[slidingWinSize_ - 1]) & polyMOD_;
            if (removeLUT_[i] != 0) {

                removeLUT_[i] = (polyMOD_ - removeLUT_[i] + 1) & polyMOD_;
            }
            /*note: % is a remainder (rather than modulus) operator*/
            /*      if a < 0,  -polyMOD_ < a % polyMOD_ <= 0       */
        }

        /*initialize the anchorMask_ for depolytermining an anchor*/
        /*note: power(2, numOfanchorMaskBits) = avgChunkSize_*/
        numOfMaskBits_ = 1;
        while ((avgChunkSize_ >> numOfMaskBits_) != 1) {

            numOfMaskBits_++;
        }
        anchorMask_ = (1 << numOfMaskBits_) - 1;
        /*initialize the value for depolytermining an anchor*/
        anchorValue_ = 0;
    } else if (ChunkerType_ == CHUNKER_FIX_SIZE_TYPE) {

        avgChunkSize_ = (int)config.getAverageChunkSize();
        minChunkSize_ = (int)config.getMinChunkSize();
        maxChunkSize_ = (int)config.getMaxChunkSize();
        ReadSize_ = config.getReadSize();
        ReadSize_ = ReadSize_ * 1024 * 1024;
        waitingForChunkingBuffer_ = new u_char[ReadSize_];
        chunkBuffer_ = new u_char[avgChunkSize_];
        memset(waitingForChunkingBuffer_, 0, ReadSize_);
        memset(chunkBuffer_, 0, avgChunkSize_);

        if (waitingForChunkingBuffer_ == NULL || chunkBuffer_ == NULL) {
            cerr << "Chunker : Memory malloc error" << endl;
            exit(1);
        }
        if (ReadSize_ % avgChunkSize_ != 0) {
            cerr << "Chunker : Setting fixed size chunking error : ReadSize_ not compat with average chunk size" << endl;
        }
    } else if (ChunkerType_ == CHUNKER_TRACE_DRIVEN_TYPE_FSL) {
        maxChunkSize_ = (int)config.getMaxChunkSize();
        chunkBuffer_ = new u_char[maxChunkSize_ + 6];
    } else if (ChunkerType_ == CHUNKER_TRACE_DRIVEN_TYPE_UBC) {
        maxChunkSize_ = (int)config.getMaxChunkSize();
        chunkBuffer_ = new u_char[maxChunkSize_ + 5];
    }
}

bool Chunker::chunking()
{
    /*fixed-size Chunker*/
    if (ChunkerType_ == CHUNKER_FIX_SIZE_TYPE) {
        fixSizeChunking();
    }
    /*variable-size Chunker*/
    if (ChunkerType_ == CHUNKER_VAR_SIZE_TYPE) {
        varSizeChunking();
    }

    if (ChunkerType_ == CHUNKER_TRACE_DRIVEN_TYPE_FSL) {
        traceDrivenChunkingFSL();
    }

    if (ChunkerType_ == CHUNKER_TRACE_DRIVEN_TYPE_UBC) {
        traceDrivenChunkingUBC();
    }

    return true;
}

void Chunker::fixSizeChunking()
{
#if SYSTEM_BREAK_DOWN == 1
    double insertTime = 0;
    double readFileTime = 0;
    long diff;
    double second;
#endif
    std::ifstream& fin = getChunkingFile();
    uint64_t chunkIDCounter = 0;
    memset(chunkBuffer_, 0, sizeof(u_char) * avgChunkSize_);
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
    /*start chunking*/
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartChunker, NULL);
#endif
    while (true) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunkerReadFile, NULL);
#endif
        memset((char*)waitingForChunkingBuffer_, 0, sizeof(u_char) * ReadSize_);
        fin.read((char*)waitingForChunkingBuffer_, sizeof(u_char) * ReadSize_);
        uint64_t totalReadSize = fin.gcount();
        fileSize += totalReadSize;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunkerReadFile, NULL);
        diff = 1000000 * (timeendChunkerReadFile.tv_sec - timestartChunkerReadFile.tv_sec) + timeendChunkerReadFile.tv_usec - timestartChunkerReadFile.tv_usec;
        second = diff / 1000000.0;
        readFileTime += second;
#endif
        uint64_t chunkedSize = 0;
        if (totalReadSize == ReadSize_) {
            while (chunkedSize < totalReadSize) {
                memset(chunkBuffer_, 0, sizeof(u_char) * avgChunkSize_);
                memcpy(chunkBuffer_, waitingForChunkingBuffer_ + chunkedSize, avgChunkSize_);
                Data_t tempChunk;
                tempChunk.chunk.ID = chunkIDCounter;
                tempChunk.chunk.logicDataSize = avgChunkSize_;
                memcpy(tempChunk.chunk.logicData, chunkBuffer_, avgChunkSize_);
                memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
                FingerprinterObj_->insertMQ(tempChunk);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunkerInsertMQ, NULL);
                diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
                second = diff / 1000000.0;
                insertTime += second;
#endif
                chunkIDCounter++;
                chunkedSize += avgChunkSize_;
            }
        } else {
            uint64_t retSize = 0;
            while (chunkedSize < totalReadSize) {
                memset(chunkBuffer_, 0, sizeof(u_char) * avgChunkSize_);
                Data_t tempChunk;
                if (retSize > avgChunkSize_) {

                    memcpy(chunkBuffer_, waitingForChunkingBuffer_ + chunkedSize, avgChunkSize_);

                    tempChunk.chunk.ID = chunkIDCounter;
                    tempChunk.chunk.logicDataSize = avgChunkSize_;
                    memcpy(tempChunk.chunk.logicData, chunkBuffer_, avgChunkSize_);
                    memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                } else {

                    memcpy(chunkBuffer_, waitingForChunkingBuffer_ + chunkedSize, retSize);

                    tempChunk.chunk.ID = chunkIDCounter;
                    tempChunk.chunk.logicDataSize = retSize;
                    memcpy(tempChunk.chunk.logicData, chunkBuffer_, retSize);
                    memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                }
                retSize = totalReadSize - chunkedSize;
                tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
                FingerprinterObj_->insertMQ(tempChunk);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunkerInsertMQ, NULL);
                diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
                second = diff / 1000000.0;
                insertTime += second;
#endif
                chunkIDCounter++;
                chunkedSize += avgChunkSize_;
            }
        }
        if (fin.eof()) {
            break;
        }
    }
    fileRecipe_.recipe.fileRecipeHead.totalChunkNumber = chunkIDCounter;
    fileRecipe_.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCounter;
    fileRecipe_.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe_.recipe.keyRecipeHead.fileSize = fileRecipe_.recipe.fileRecipeHead.fileSize;
    fileRecipe_.dataType = DATA_TYPE_RECIPE;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
    FingerprinterObj_->insertMQ(fileRecipe_);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendChunkerInsertMQ, NULL);
    diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
    second = diff / 1000000.0;
    insertTime += second;
#endif
    bool jobDoneFlagStatus = FingerprinterObj_->editJobDoneFlag();
    if (jobDoneFlagStatus == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendChunker, NULL);
    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
    second = diff / 1000000.0;
    cout << "Chunker : total read file time = " << setbase(10) << readFileTime << " s" << endl;
    cout << "Chunker : total chunking time = " << setbase(10) << second - (insertTime + readFileTime) << " s" << endl;
#endif
    cout << "Chunker : Fixed chunking over:\n\t  Total file size = " << fileRecipe_.recipe.fileRecipeHead.fileSize << " Byte;\n\t  Total chunk number = " << fileRecipe_.recipe.fileRecipeHead.totalChunkNumber << endl;
}

void Chunker::varSizeChunking()
{
#if SYSTEM_BREAK_DOWN == 1
    double insertTime = 0;
    double readFileTime = 0;
    long diff;
    double second;
#endif
    uint16_t winFp = 0;
    uint64_t chunkBufferCnt = 0, chunkIDCnt = 0;
    ifstream& fin = getChunkingFile();
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
/*start chunking*/
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartChunker, NULL);
#endif
    while (true) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunkerReadFile, NULL);
#endif
        memset((char*)waitingForChunkingBuffer_, 0, sizeof(u_char) * ReadSize_);
        fin.read((char*)waitingForChunkingBuffer_, sizeof(u_char) * ReadSize_);
        int len = fin.gcount();
        fileSize += len;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunkerReadFile, NULL);
        diff = 1000000 * (timeendChunkerReadFile.tv_sec - timestartChunkerReadFile.tv_sec) + timeendChunkerReadFile.tv_usec - timestartChunkerReadFile.tv_usec;
        second = diff / 1000000.0;
        readFileTime += second;
#endif
        memset(chunkBuffer_, 0, sizeof(u_char) * maxChunkSize_);
        for (int i = 0; i < len; i++) {

            chunkBuffer_[chunkBufferCnt] = waitingForChunkingBuffer_[i];

            /*full fill sliding window*/
            if (chunkBufferCnt < slidingWinSize_) {
                winFp = winFp + (chunkBuffer_[chunkBufferCnt] * powerLUT_[slidingWinSize_ - chunkBufferCnt - 1]) & polyMOD_; //Refer to doc/Chunking.md hash function:RabinChunker
                chunkBufferCnt++;
                continue;
            }
            winFp &= (polyMOD_);

            /*slide window*/
            unsigned short int v = chunkBuffer_[chunkBufferCnt - slidingWinSize_]; //queue
            winFp = ((winFp + removeLUT_[v]) * polyBase_ + chunkBuffer_[chunkBufferCnt]) & polyMOD_; //remove queue front and add queue tail
            chunkBufferCnt++;

            /*chunk's size less than minChunkSize_*/
            if (chunkBufferCnt < minChunkSize_) {
                continue;
            }

            /*find chunk pattern*/
            if ((winFp & anchorMask_) == anchorValue_) {
                Data_t tempChunk;
                tempChunk.chunk.ID = chunkIDCnt;
                tempChunk.chunk.logicDataSize = chunkBufferCnt;
                memcpy(tempChunk.chunk.logicData, chunkBuffer_, chunkBufferCnt);
                memset(chunkBuffer_, 0, sizeof(u_char) * maxChunkSize_);
                memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
                FingerprinterObj_->insertMQ(tempChunk);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunkerInsertMQ, NULL);
                diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
                second = diff / 1000000.0;
                insertTime += second;
#endif
                chunkIDCnt++;
                chunkBufferCnt = 0;
                winFp = 0;
            }

            /*chunk's size exceed maxChunkSize_*/
            if (chunkBufferCnt >= maxChunkSize_) {
                Data_t tempChunk;
                tempChunk.chunk.ID = chunkIDCnt;
                tempChunk.chunk.logicDataSize = chunkBufferCnt;
                memcpy(tempChunk.chunk.logicData, chunkBuffer_, chunkBufferCnt);
                memset(chunkBuffer_, 0, sizeof(u_char) * maxChunkSize_);
                memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
                FingerprinterObj_->insertMQ(tempChunk);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunkerInsertMQ, NULL);
                diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
                second = diff / 1000000.0;
                insertTime += second;
#endif
                chunkIDCnt++;
                chunkBufferCnt = 0;
                winFp = 0;
            }
        }
        if (fin.eof()) {
            break;
        }
    }

    /*add final chunk*/
    if (chunkBufferCnt != 0) {
        Data_t tempChunk;
        tempChunk.chunk.ID = chunkIDCnt;
        tempChunk.chunk.logicDataSize = chunkBufferCnt;
        memcpy(tempChunk.chunk.logicData, chunkBuffer_, chunkBufferCnt);
        memset(chunkBuffer_, 0, sizeof(u_char) * maxChunkSize_);
        memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
        tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
        FingerprinterObj_->insertMQ(tempChunk);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunkerInsertMQ, NULL);
        diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
        second = diff / 1000000.0;
        insertTime += second;
#endif
        chunkIDCnt++;
        chunkBufferCnt = 0;
        winFp = 0;
    }
    fileRecipe_.recipe.fileRecipeHead.totalChunkNumber = chunkIDCnt;
    fileRecipe_.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCnt;
    fileRecipe_.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe_.recipe.keyRecipeHead.fileSize = fileRecipe_.recipe.fileRecipeHead.fileSize;
    fileRecipe_.dataType = DATA_TYPE_RECIPE;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartChunkerInsertMQ, NULL);
#endif
    FingerprinterObj_->insertMQ(fileRecipe_);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendChunkerInsertMQ, NULL);
    diff = 1000000 * (timeendChunkerInsertMQ.tv_sec - timestartChunkerInsertMQ.tv_sec) + timeendChunkerInsertMQ.tv_usec - timestartChunkerInsertMQ.tv_usec;
    second = diff / 1000000.0;
    insertTime += second;
#endif
    bool jobDoneFlagStatus = FingerprinterObj_->editJobDoneFlag();
    if (jobDoneFlagStatus == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendChunker, NULL);
    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
    second = diff / 1000000.0;
    cout << "Chunker : total read file time = " << setbase(10) << readFileTime << " s" << endl;
    cout << "Chunker : total chunking time = " << setbase(10) << second - (insertTime + readFileTime) << " s" << endl;
#endif
    cout << "Chunker : variable size chunking over:\n\t  Total file size = " << fileRecipe_.recipe.fileRecipeHead.fileSize << " Byte;\n\t  Total chunk number = " << fileRecipe_.recipe.fileRecipeHead.totalChunkNumber << endl;
    return;
}

void Chunker::traceDrivenChunkingFSL()
{
#if SYSTEM_BREAK_DOWN == 1
    double chunkTime = 0;
    double readFileTime = 0;
    long diff;
    double second;
#endif
    std::ifstream& fin = getChunkingFile();
    uint64_t chunkIDCounter = 0;
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
    char readLineBuffer[256];
    string readLineStr;
    /*start chunking*/
    getline(fin, readLineStr);
    while (true) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunkerReadFile, NULL);
#endif
        getline(fin, readLineStr);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunkerReadFile, NULL);
        diff = 1000000 * (timeendChunkerReadFile.tv_sec - timestartChunkerReadFile.tv_sec) + timeendChunkerReadFile.tv_usec - timestartChunkerReadFile.tv_usec;
        second = diff / 1000000.0;
        readFileTime += second;
#endif
        if (fin.eof()) {
            break;
        }
        memset(readLineBuffer, 0, 256);
        memcpy(readLineBuffer, (char*)readLineStr.c_str(), readLineStr.length());
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker, NULL);
#endif
        u_char chunkFp[7];
        memset(chunkFp, 0, 7);
        char* item;
        item = strtok(readLineBuffer, ":\t\n ");
        for (int index = 0; item != NULL && index < 6; index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunkFp[6] = '\0';
        auto size = atoi(item);
        int copySize = 0;
        memset(chunkBuffer_, 0, sizeof(char) * maxChunkSize_ + 6);
        if (size > maxChunkSize_) {
            continue;
        }
        while (copySize < size) {
            memcpy(chunkBuffer_ + copySize, chunkFp, 6);
            copySize += 6;
        }
        Data_t tempChunk;
        tempChunk.chunk.ID = chunkIDCounter;
        tempChunk.chunk.logicDataSize = size;
        memcpy(tempChunk.chunk.logicData, chunkBuffer_, size);
        memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
        tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker, NULL);
        diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
        second = diff / 1000000.0;
        chunkTime += second;
#endif
        FingerprinterObj_->insertMQ(tempChunk);
        chunkIDCounter++;
        fileSize += size;
    }
    fileRecipe_.recipe.fileRecipeHead.totalChunkNumber = chunkIDCounter;
    fileRecipe_.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCounter;
    fileRecipe_.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe_.recipe.keyRecipeHead.fileSize = fileRecipe_.recipe.fileRecipeHead.fileSize;
    fileRecipe_.dataType = DATA_TYPE_RECIPE;
    FingerprinterObj_->insertMQ(fileRecipe_);
    bool jobDoneFlagStatus = FingerprinterObj_->editJobDoneFlag();
    if (jobDoneFlagStatus == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    cout << "Chunker : total read file time = " << setbase(10) << readFileTime << " s" << endl;
    cout << "Chunker : total chunking time = " << chunkTime << " s" << endl;
#endif
    cout << "Chunker : trace gen over:\n\t  Total file size = " << fileRecipe_.recipe.fileRecipeHead.fileSize << " Byte;\n\t  Total chunk number = " << fileRecipe_.recipe.fileRecipeHead.totalChunkNumber << endl;
}

void Chunker::traceDrivenChunkingUBC()
{
#if SYSTEM_BREAK_DOWN == 1
    double chunkTime = 0;
    double readFileTime = 0;
    long diff;
    double second;
#endif
    std::ifstream& fin = getChunkingFile();
    uint64_t chunkIDCounter = 0;
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
    char readLineBuffer[256];
    string readLineStr;
    /*start chunking*/
    getline(fin, readLineStr);
    while (true) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunkerReadFile, NULL);
#endif
        getline(fin, readLineStr);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunkerReadFile, NULL);
        diff = 1000000 * (timeendChunkerReadFile.tv_sec - timestartChunkerReadFile.tv_sec) + timeendChunkerReadFile.tv_usec - timestartChunkerReadFile.tv_usec;
        second = diff / 1000000.0;
        readFileTime += second;
#endif
        if (fin.eof()) {
            break;
        }
        memset(readLineBuffer, 0, 256);
        memcpy(readLineBuffer, (char*)readLineStr.c_str(), readLineStr.length());

#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker, NULL);
#endif
        u_char chunkFp[6];
        memset(chunkFp, 0, 6);
        char* item;
        item = strtok(readLineBuffer, ":\t\n ");
        for (int index = 0; item != NULL && index < 5; index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunkFp[5] = '\0';
        auto size = atoi(item);
        int copySize = 0;
        memset(chunkBuffer_, 0, sizeof(char) * maxChunkSize_ + 5);
        if (size > maxChunkSize_) {
            continue;
        }
        while (copySize < size) {
            memcpy(chunkBuffer_ + copySize, chunkFp, 5);
            copySize += 5;
        }

        Data_t tempChunk;
        tempChunk.chunk.ID = chunkIDCounter;
        tempChunk.chunk.logicDataSize = size;
        memcpy(tempChunk.chunk.logicData, chunkBuffer_, size);
        memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
        tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker, NULL);
        diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
        second = diff / 1000000.0;
        chunkTime += second;
#endif
        FingerprinterObj_->insertMQ(tempChunk);
        chunkIDCounter++;
        fileSize += size;
    }
    fileRecipe_.recipe.fileRecipeHead.totalChunkNumber = chunkIDCounter;
    fileRecipe_.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCounter;
    fileRecipe_.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe_.recipe.keyRecipeHead.fileSize = fileRecipe_.recipe.fileRecipeHead.fileSize;
    fileRecipe_.dataType = DATA_TYPE_RECIPE;
    FingerprinterObj_->insertMQ(fileRecipe_);
    bool jobDoneFlagStatus = FingerprinterObj_->editJobDoneFlag();
    if (jobDoneFlagStatus == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
#if SYSTEM_BREAK_DOWN == 1
    cout << "Chunker : total read file time = " << setbase(10) << readFileTime << " s" << endl;
    cout << "Chunker : total chunking time is" << chunkTime << " s" << endl;
#endif
    cout << "Chunker : trace gen over:\n\t  Total file size = " << fileRecipe_.recipe.fileRecipeHead.fileSize << " Byte;\n\t  Total chunk number = " << fileRecipe_.recipe.fileRecipeHead.totalChunkNumber << endl;
}
