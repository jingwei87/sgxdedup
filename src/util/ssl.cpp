#include "ssl.hpp"
#include <fcntl.h>

bool IsFileUsed(const char* filePath)
{
    bool ret = false;
    if ((access(filePath, 2)) == -1) {
        ret = true;
    }
    return ret;
}

ssl::ssl(string ip, int port, int scSwitch)
{
    this->_serverIP = ip;
    this->_port = port;
    this->listenFd = socket(AF_INET, SOCK_STREAM, 0);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    memset(&_sockAddr, 0, sizeof(_sockAddr));
    string keyFile, crtFile;

    _sockAddr.sin_port = htons(port);
    _sockAddr.sin_family = AF_INET;

    switch (scSwitch) {
    case SERVERSIDE: {
#if OPENSSL_V_1_0_2 == 1
        _ctx = SSL_CTX_new(TLSv1_2_server_method());
#else
        _ctx = SSL_CTX_new(TLS_server_method());
#endif
        SSL_CTX_set_mode(_ctx, SSL_MODE_AUTO_RETRY);
        crtFile = SECRT;
        keyFile = SEKEY;
        _sockAddr.sin_addr.s_addr = htons(INADDR_ANY);
        if (bind(listenFd, (sockaddr*)&_sockAddr, sizeof(_sockAddr)) == -1) {
            cerr << "SSL : Can not bind to sockfd" << endl
                 << "\tMay cause by shutdown server before client" << endl
                 << "\tWait for 1 min and try again" << endl;
            exit(1);
        }
        if (listen(listenFd, 10) == -1) {
            cerr << "SSL : Can not set listen socket" << endl;
            exit(1);
        }
        break;
    }
    case CLIENTSIDE: {
#if OPENSSL_V_1_0_2 == 1
        _ctx = SSL_CTX_new(TLSv1_2_client_method());
#else
        _ctx = SSL_CTX_new(TLS_client_method());
#endif
        keyFile = CLKEY;
        crtFile = CLCRT;
        _sockAddr.sin_addr.s_addr = inet_addr(ip.c_str());
        break;
    };
    }
    // while (true) {
    //     if (!IsFileUsed(CACRT) && !IsFileUsed(crtFile.c_str()) && !IsFileUsed(keyFile.c_str())) {
    //         cout << "SSL : Key files not in used, Start ssl connection" << endl;
    //         break;
    //     } else {
    //         cout << "SSL : Key files status " << IsFileUsed(CACRT) << IsFileUsed(crtFile.c_str()) << IsFileUsed(keyFile.c_str()) << endl;
    //     }
    // }
    SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(_ctx, CACRT, NULL)) {
        cerr << "SSL : Wrong CA crt file at ssl.cpp:ssl(ip,port)" << endl;
        exit(1);
    }
    if (!SSL_CTX_use_certificate_file(_ctx, crtFile.c_str(), SSL_FILETYPE_PEM)) {
        cerr << "SSL : Wrong crt file at ssl.cpp:ssl(ip,port)" << endl;
        exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(_ctx, keyFile.c_str(), SSL_FILETYPE_PEM)) {
        cerr << "SSL : Wrong key file at ssl.cpp:ssl(ip,port)" << endl;
        exit(1);
    }
    if (!SSL_CTX_check_private_key(_ctx)) {
        cerr << "SSL : check private key error" << endl;
        exit(1);
    }
#if SYSTEM_DEBUG_FLAG == 1
    cout << "SSL : ssl connection to " << ip << ":" << port << " setup" << endl;
#endif
}

ssl::~ssl()
{
}
pair<int, SSL*> ssl::sslConnect()
{
    //pair<int,SSL*> ssl::sslConnect(){
    int fd;
    SSL* sslConection;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr*)&_sockAddr, sizeof(sockaddr)) < 0) {
        cerr << "SSL : ERROR Occur on ssl(fd) connect" << endl;
        exit(1);
    }
    sslConection = SSL_new(_ctx);
    SSL_set_fd(sslConection, fd);
    SSL_connect(sslConection);

    //_fdList.push_back(fd);
    //_sslList.push_back(sslConection);
    return make_pair(fd, sslConection);
}

pair<int, SSL*> ssl::sslListen()
{
    //pair<int,SSL*> ssl::sslListen(){
    int fd;
    fd = accept(listenFd, (struct sockaddr*)NULL, NULL);
    SSL* sslConection = SSL_new(_ctx);
    SSL_set_fd(sslConection, fd);
    SSL_accept(sslConection);

    //_fdList.push_back(fd);
    //_sslList.push_back(sslConection);
    return make_pair(fd, sslConection);
}

bool ssl::recv(SSL* connection, char* data, int& dataSize)
{
    int recvd = 0, len = 0;
    if (SSL_read(connection, (char*)&len, sizeof(int)) == 0) {
        return false;
    }
    while (recvd < len) {
        recvd += SSL_read(connection, data + recvd, len - recvd);
    }
    dataSize = len;
    return true;
}

bool ssl::send(SSL* connection, char* data, int dataSize)
{
    if (SSL_write(connection, (char*)&dataSize, sizeof(int)) == 0) {
        return false;
    }
    int sendSize = 0;
    while (sendSize < dataSize) {
        sendSize += SSL_write(connection, data + sendSize, dataSize - sendSize);
    }
    return true;
}
