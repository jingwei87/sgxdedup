#include "dedupCore.hpp"

extern Database fp2ChunkDB;
extern Configure config;

void PRINT_BYTE_ARRAY_DEDUP_CORE(
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

DedupCore::DedupCore()
{
}

DedupCore::~DedupCore()
{
}

bool DedupCore::dedupByHash(u_char* inputHashList, int chunkNumber, bool* out, int& requiredChunkNumber)
{
    string tmpdata;
    for (int i = 0; i < chunkNumber; i++) {
        string queryKey((char*)(inputHashList + i * CHUNK_HASH_SIZE), CHUNK_HASH_SIZE);
        bool fp2ChunkDBQueryStatus = fp2ChunkDB.query(queryKey, tmpdata);
        if (fp2ChunkDBQueryStatus) {
            continue;
        } else {
            out[i] = true;
            requiredChunkNumber++;
        }
    }
    return true;
}
