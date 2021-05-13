#include "keyServer.hpp"
#include <signal.h>

Configure config("config.json");
keyServer* server;

struct timeval timestartKeyServerMain;
struct timeval timeendKeyServerMain;

void CTRLC(int s)
{
    cerr << "KeyManager exit with keyboard interrupt" << endl;
    delete server;
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

    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    server = new keyServer(keySecurityChannelTemp);
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
    gettimeofday(&timestartKeyServerMain, NULL);
#endif
    server->runRemoteAttestationInit();
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKeyServerMain, NULL);
    diff = 1000000 * (timeendKeyServerMain.tv_sec - timestartKeyServerMain.tv_sec) + timeendKeyServerMain.tv_usec - timestartKeyServerMain.tv_usec;
    second = diff / 1000000.0;
    cout << "KeyServerMain : init key server enclave time = " << second << " s" << endl;
#endif
    cerr << "KeyServerMain : key server remote attestation done, start provide service" << endl;
#if KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CFB
    th = new boost::thread(boost::bind(&keyServer::runRAwithSPRequest, server));
    th->detach();
    th = new boost::thread(boost::bind(&keyServer::runSessionKeyUpdate, server));
    th->detach();
#elif KEY_GEN_METHOD_TYPE == KEY_GEN_SGX_CTR
    th = new boost::thread(boost::bind(&keyServer::runRAwithSPRequest, server));
    th->detach();
    th = new boost::thread(boost::bind(&keyServer::runSessionKeyUpdate, server));
    th->detach();
    th = new boost::thread(boost::bind(&keyServer::runCTRModeMaskGenerate, server));
    th->detach();
#endif
    while (true) {
        SSL* sslConnection = keySecurityChannelTemp->sslListen().second;
        th = new boost::thread(boost::bind(&keyServer::runKeyGenerateThread, server, sslConnection));
        th->detach();
    }
    return 0;
}