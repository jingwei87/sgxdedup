#include "../enclave/include/powServer.hpp"
#include "boost/thread.hpp"
#include "configure.hpp"
#include "dataSR.hpp"
#include "database.hpp"
#include "dedupCore.hpp"
#include "messageQueue.hpp"
#include "storageCore.hpp"
#include <signal.h>
Configure config("config.json");

Database fp2ChunkDB;
Database fileName2metaDB;

DataSR* dataSRObj;
StorageCore* storageObj;
DedupCore* dedupCoreObj;
powServer* powServerObj;

vector<boost::thread*> thList;

void CTRLC(int s)
{
    cerr << "Server exit with keyboard interrupt" << endl;

    if (storageObj != nullptr)
        delete storageObj;

    if (dataSRObj != nullptr)
        delete dataSRObj;

    if (dedupCoreObj != nullptr)
        delete dedupCoreObj;

    if (powServerObj != nullptr)
        delete powServerObj;
    // for (auto th : thList) {
    //     th->join();
    // }
    exit(0);
}

int main()
{

    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    fp2ChunkDB.openDB(config.getFp2ChunkDBName());
    fileName2metaDB.openDB(config.getFp2MetaDBame());

    ssl* dataSecurityChannelTemp = new ssl(config.getStorageServerIP(), config.getStorageServerPort(), SERVERSIDE);
    ssl* powSecurityChannelTemp = new ssl(config.getStorageServerIP(), config.getPOWServerPort(), SERVERSIDE);

    dedupCoreObj = new DedupCore();
    storageObj = new StorageCore();
    powServerObj = new powServer();
    dataSRObj = new DataSR(storageObj, dedupCoreObj, powServerObj, powSecurityChannelTemp, dataSecurityChannelTemp);

    boost::thread* th;
    th = new boost::thread(boost::bind(&DataSR::runKeyServerRemoteAttestation, dataSRObj));
    thList.push_back(th);
    th->detach();
    th = new boost::thread(boost::bind(&DataSR::runKeyServerSessionKeyUpdate, dataSRObj));
    thList.push_back(th);
    th->detach();

    boost::thread::attributes attrs;
    attrs.set_stack_size(100 * 1024 * 1024);
    while (true) {
        SSL* sslConnectionData = dataSecurityChannelTemp->sslListen().second;
        th = new boost::thread(attrs, boost::bind(&DataSR::runData, dataSRObj, sslConnectionData));
        thList.push_back(th);
        SSL* sslConnectionPow = powSecurityChannelTemp->sslListen().second;
        th = new boost::thread(attrs, boost::bind(&DataSR::runPow, dataSRObj, sslConnectionPow));
        thList.push_back(th);
    }

    return 0;
}