#ifndef SGXDEDUP_CONFIGURE_HPP
#define SGXDEDUP_CONFIGURE_HPP

#include "systemSettings.hpp"
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace std;

class Configure {
private:
    // following settings configure by macro set

    // chunking settings
    uint64_t _chunkingType; // varSize \ fixedSize \ simple
    uint64_t _maxChunkSize;
    uint64_t _minChunkSize;
    uint64_t _averageChunkSize;
    uint64_t _slidingWinSize;
    uint64_t _ReadSize; //128M per time

    // key management settings
    uint64_t _keyEnclaveThreadNumber;
    std::vector<std::string> _keyServerIP;
    std::vector<int> _keyServerPort;
    int _keyServerRArequestPort;
    int _keyBatchSize;
    uint32_t _keyRegressionMaxTimes;
    uint32_t _keyRegressionIntervals;

    //POW settings
    int _POWQuoteType; //0x00 linkable; 0x01 unlinkable
    int _POWIasVersion;
    int _POWServerPort;
    std::string _POWEnclaveName;
    std::string _POWSPID;
    int _POWIasServerType; //0 for develop; 1 for production
    uint64_t _POWBatchSize;
    std::string _POWPriSubscriptionKey;
    std::string _POWSecSubscriptionKey;

    //km enclave settings
    int _KMQuoteType; //0x00 linkable; 0x01 unlinkable
    int _KMIasVersion;
    int _KMServerPort;
    std::string _KMEnclaveName;
    std::string _KMSPID;
    int _KMIasServerType; //0 for develop; 1 for production
    std::string _KMPriSubscriptionKey;
    std::string _KMSecSubscriptionKey;

    // storage management settings
    std::vector<std::string> _storageServerIP;
    std::vector<int> _storageServerPort;
    uint64_t _maxContainerSize;

    //server setting
    std::string _RecipeRootPath;
    std::string _containerRootPath;
    std::string _fp2ChunkDBName;
    std::string _fp2MetaDBame;
    uint64_t _raSessionKeylifeSpan;

    //client settings
    int _clientID;
    int _sendChunkBatchSize;
    int _sendRecipeBatchSize;

    // any additional settings

public:
    //  Configure(std::ifstream& confFile); // according to setting json to init configure class
    Configure(std::string path);

    Configure();

    ~Configure();

    void readConf(std::string path);

    // chunking settings
    uint64_t getChunkingType();
    uint64_t getMaxChunkSize();
    uint64_t getMinChunkSize();
    uint64_t getAverageChunkSize();
    uint64_t getSlidingWinSize();
    uint64_t getSegmentSize();
    uint64_t getReadSize();

    // key management settings
    uint64_t getKeyServerNumber();
    uint64_t getKeyEnclaveThreadNumber();
    std::string getKeyServerIP();
    //std::vector<std::string> getkeyServerIP();
    int getKeyServerPort();
    //std::vector<int> getKeyServerPort();
    int getkeyServerRArequestPort();
    int getKeyBatchSize();
    uint32_t getKeyRegressionMaxTimes();
    uint32_t getKeyRegressionIntervals(); // unit: sec

    //pow settings
    int getPOWQuoteType();
    int getPOWIASVersion();
    int getPOWServerPort();
    std::string getPOWEnclaveName();
    std::string getPOWSPID();
    int getPOWIASServerType();
    uint64_t getPOWBatchSize();
    std::string getPOWPriSubscriptionKey();
    std::string getPOWSecSubscriptionKey();

    //km settings
    int getKMQuoteType();
    int getKMIASVersion();
    int getKMServerPort();
    std::string getKMEnclaveName();
    std::string getKMSPID();
    int getKMIASServerType();
    std::string getKMPriSubscriptionKey();
    std::string getKMSecSubscriptionKey();

    // storage management settings
    uint64_t getStorageServerNumber();
    std::string getStorageServerIP();
    //std::vector<std::string> getStorageServerIP();

    int getStorageServerPort();
    //std::vector<int> getStorageServerPort();

    uint64_t getMaxContainerSize();

    //server settings
    std::string getRecipeRootPath();
    std::string getContainerRootPath();
    std::string getFp2ChunkDBName();
    std::string getFp2MetaDBame();
    uint64_t getRASessionKeylifeSpan();

    //client settings
    int getClientID();
    int getSendChunkBatchSize();
    int getSendRecipeBatchSize();
};

#endif //SGXDEDUP_CONFIGURE_HPP
