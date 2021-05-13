#ifndef SGXDEDUP_FINGERPRINTER_HPP
#define SGXDEDUP_FINGERPRINTER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "keyClient.hpp"
#include "messageQueue.hpp"

class Fingerprinter {
private:
    messageQueue<Data_t>* inputMQ_;
    KeyClient* keyClientObj_;
    CryptoPrimitive* cryptoObj_;

public:
    Fingerprinter(KeyClient* keyClientObjTemp);
    ~Fingerprinter();
    void run();
    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool editJobDoneFlag();
};

#endif //SGXDEDUP_FINGERPRINTER_HPP
