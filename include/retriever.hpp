#ifndef SGXDEDUP_RETRIEVER_HPP
#define SGXDEDUP_RETRIEVER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "recvDecode.hpp"
#include <bits/stdc++.h>
#include <boost/thread.hpp>

using namespace std;

class Retriever {
private:
    std::ofstream retrieveFile_;
    RecvDecode* recvDecodeObj_;
    uint32_t totalChunkNumber_;

public:
    Retriever(string fileName, RecvDecode*& recvDecodeObjTemp);
    ~Retriever();
    void run();
};

#endif //SGXDEDUP_RETRIEVER_HPP
