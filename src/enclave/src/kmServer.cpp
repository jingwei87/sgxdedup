#include "kmServer.hpp"
extern Configure config;
//./sp -s 928A6B0E3CDDAD56EB3BADAA3B63F71F -A ./client.crt
// -C ./client.crt --ias-cert-key=./client.pem -x -d -v
// -A AttestationReportSigningCACert.pem -C client.crt
// -s 797F0D90EE75B24B554A73AB01FD3335 -Y client.pem

void PRINT_BYTE_ARRAY_KMS(
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

kmServer::kmServer(ssl* raSecurityChannel, SSL* sslConnection)
{
    if (!cert_load_file(&_signing_ca, IAS_SIGNING_CA_FILE_KM)) {
        cerr << "KmServer : can not load IAS Signing Cert CA" << endl;
        exit(1);
    }

    _store = cert_init_ca(_signing_ca);
    if (_store == nullptr) {
        cerr << "KmServer : can not init cert file" << endl;
        exit(1);
    }

    string spid = config.getKMSPID();
    if (spid.length() != 32) {
        cerr << "KmServer : SPID must be 32-byte hex string" << endl;
        exit(1);
    }

    from_hexstring((unsigned char*)&_spid, (const void*)&spid[0], 16);

    _ias = new IAS_Connection(
        config.getKMIASServerType(),
        0,
        (char*)(config.getKMPriSubscriptionKey().c_str()),
        (char*)(config.getKMSecSubscriptionKey().c_str()));
    _ias->agent("wget");
    // _ias->client_cert(IAS_CERT_FILE, "PEM");
    // _ias->client_key(IAS_CLIENT_KEY, nullptr);
    _ias->proxy_mode(IAS_PROXY_NONE);
    _ias->cert_store(_store);
    _ias->ca_bundle(CA_BUNDLE);

    // _ias = new IAS_Connection(config.getKMIASServerType(), 0);
    // _ias->client_cert(IAS_CERT_FILE, "PEM");
    // _ias->client_key(IAS_CLIENT_KEY, nullptr);
    // _ias->proxy_mode(IAS_PROXY_NONE);
    // _ias->cert_store(_store);
    // _ias->ca_bundle(CA_BUNDLE);

    _quote_type = config.getKMQuoteType();
    _service_private_key = key_private_from_bytes(def_service_private_key_km);
    _iasVersion = config.getKMIASVersion();
    raSecurityChannel_ = raSecurityChannel;
    sslConnection_ = sslConnection;
}

bool kmServer::process_msg01(enclaveSession* session, sgx_msg01_t& msg01, sgx_ra_msg2_t& msg2)
{

    EVP_PKEY* Gb;
    unsigned char digest[32], r[32], s[32], gb_ga[128];

    msg01.msg0_extended_epid_group_id = 0;
    if (msg01.msg0_extended_epid_group_id != 0) {
        cerr << "KmServer : msg0 Extended Epid Group ID is not zero.  Exiting." << endl;
        return false;
    }

    memcpy(&session->msg1, &msg01.msg1, sizeof(sgx_ra_msg1_t));

    Gb = key_generate();
    if (Gb == nullptr) {
        cerr << "KmServer : can not create session key" << endl;
        return false;
    }

    if (!derive_kdk(Gb, session->kdk, msg01.msg1.g_a)) {
        cerr << "KmServer : can not derive KDK" << endl;
        return false;
    }

    cmac128(session->kdk, (unsigned char*)("\x01SMK\x00\x80\x00"), 7,
        session->smk);

    //build msg2
    memset(&msg2, 0, sizeof(sgx_ra_msg2_t));

    key_to_sgx_ec256(&msg2.g_b, Gb);
    memcpy(&msg2.spid, &_spid, sizeof(sgx_spid_t));
    msg2.quote_type = _quote_type;
    msg2.kdf_id = 1;

    if (!get_sigrl(msg01.msg1.gid, (char*)&msg2.sig_rl, &msg2.sig_rl_size)) {
        cerr << "KmServer : can not retrieve sigrl form ias server" << endl;
        free(Gb);
        return false;
    }

    memcpy(gb_ga, &msg2.g_b, 64);
    memcpy(session->g_b, &msg2.g_b, 64);

    memcpy(&gb_ga[64], &session->msg1.g_a, 64);
    memcpy(session->g_a, &session->msg1.g_a, 64);

    ecdsa_sign(gb_ga, 128, _service_private_key, r, s, digest);
    reverse_bytes(&msg2.sign_gb_ga.x, r, 32);
    reverse_bytes(&msg2.sign_gb_ga.y, s, 32);

    cmac128(session->smk, (unsigned char*)&msg2, 148, (unsigned char*)&msg2.mac);
    free(Gb);
    return true;
}

bool kmServer::derive_kdk(EVP_PKEY* Gb, unsigned char* kdk, sgx_ec256_public_t g_a)
{
    unsigned char* Gab_x;
    unsigned char cmacKey[16];
    size_t len;
    EVP_PKEY* Ga;
    Ga = key_from_sgx_ec256(&g_a);
    if (Ga == nullptr) {
        cerr << "KmServer : can not get ga from msg1" << endl;
        free(Ga);
        return false;
    }
    Gab_x = key_shared_secret(Gb, Ga, &len);
    if (Gab_x == nullptr) {
        cerr << "KmServer : can not get shared secret" << endl;
        free(Ga);
        return false;
    }
    reverse_bytes(Gab_x, Gab_x, len);

    memset(cmacKey, 0, sizeof(cmacKey));
    cmac128(cmacKey, Gab_x, len, kdk);
    free(Ga);
    return true;
}

bool kmServer::get_sigrl(uint8_t* gid, char* sig_rl, uint32_t* sig_rl_size)
{
    IAS_Request* req = nullptr;

    req = new IAS_Request(_ias, _iasVersion);
    if (req == nullptr) {
        cerr << "KmServer : can not make ias request" << endl;
        delete req;
        return false;
    }
    string sigrlstr;
    if (req->sigrl(*(uint32_t*)gid, sigrlstr) != IAS_OK) {
        cerr << "KmServer : ias get sigrl error, status != ok" << endl;
        delete req;
        return false;
    }

    memcpy(sig_rl, &sigrlstr[0], sigrlstr.length());
    if (sig_rl == nullptr) {
        delete req;
        return false;
    }
    *sig_rl_size = (uint32_t)sigrlstr.length();
    delete req;
    return true;
}

bool kmServer::process_msg3(enclaveSession* current, sgx_ra_msg3_t* msg3,
    ra_msg4_t& msg4, uint32_t quote_sz)
{

    if (CRYPTO_memcmp(&msg3->g_a, &current->msg1.g_a,
            sizeof(sgx_ec256_public_t))) {
        cerr << "KmServer : msg1.ga != msg3.ga" << endl;
        return false;
    }
    sgx_mac_t msgMAC;
    cmac128(current->smk, (unsigned char*)&msg3->g_a, sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_sz, (unsigned char*)msgMAC);
    if (CRYPTO_memcmp(msg3->mac, msgMAC, sizeof(sgx_mac_t))) {
        cerr << "KmServer : broken msg3 from client" << endl;
        return false;
    }
    char* b64quote;
    b64quote = base64_encode((char*)&msg3->quote, quote_sz);
    sgx_quote_t* q;
    q = (sgx_quote_t*)msg3->quote;
    if (memcmp(current->msg1.gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t))) {
        cerr << "KmServer : Attestation failed. Differ gid" << endl;
        return false;
    }
    if (get_attestation_report(b64quote, msg3->ps_sec_prop, &msg4)) {
        free(b64quote);
        unsigned char vfy_rdata[64];
        unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

        sgx_report_body_t* r = (sgx_report_body_t*)&q->report_body;

        memset(vfy_rdata, 0, 64);

        /*
         * Verify that the first 64 bytes of the report data (inside
         * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
         *
         * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
         *
         * where || denotes concatenation.
         */
        // ifstream fin(path, ifstream::binary);
        // recipe.recipe.fileRecipeHead.fileSize = fin.tellg();
        // fin.close();
        /* Derive VK */

        cmac128(current->kdk, (unsigned char*)("\x01VK\x00\x80\x00"),
            6, current->vk);

        /* Build our plaintext */

        memcpy(msg_rdata, current->g_a, 64);
        memcpy(&msg_rdata[64], current->g_b, 64);
        memcpy(&msg_rdata[128], current->vk, 16);

        /* SHA-256 hash */

        sha256_digest(msg_rdata, 144, vfy_rdata);

        if (CRYPTO_memcmp((void*)vfy_rdata, (void*)&r->report_data,
                64)) {

            cerr << "KmServer : Report verification failed." << endl;
            return false;
        }

        /*
         * A real service provider would validate that the pow_enclave
         * report is from an pow_enclave that they recognize. Namely,
         * that the MRSIGNER matches our signing key, and the MRENCLAVE
         * hash matches an pow_enclave that we compiled.
         *
         * Other policy decisions might include examining ISV_SVN to
         * prevent outdated/deprecated software from successfully
         * attesting, and ensuring the TCB is not out of date.
         */

        /*
         * If the pow_enclave is trusted, derive the MK and SK. Also get
         * SHA256 hashes of these so we can verify there's a shared
         * secret between us and the client.
         */

        if (msg4.status) {

            cmac128(current->kdk, (unsigned char*)("\x01MK\x00\x80\x00"),
                6, current->mk);
            cmac128(current->kdk, (unsigned char*)("\x01SK\x00\x80\x00"),
                6, current->sk);
            current->enclaveTrusted = true;
            return true;
        } else {
            return false;
        }
    } else {
        free(b64quote);
        cerr << "KmServer : Attestation failed" << endl;
        return false;
    }
    return true;
}

bool kmServer::get_attestation_report(const char* b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t* msg4)
{
    IAS_Request* req = nullptr;
    map<string, string> payload;
    vector<string> messages;
    ias_error_t status;
    string content;

    req = new IAS_Request(_ias, (uint16_t)_iasVersion);
    if (req == nullptr) {
        cerr << "KmServer : Exception while creating IAS request object" << endl;
        messages.clear();
        return false;
    }

    payload.insert(make_pair("isvEnclaveQuote", b64quote));

    status = req->report(payload, content, messages);
    if (status == IAS_OK) {
        using namespace json;
        JSON reportObj = JSON::Load(content);

        /*
         * If the report returned a version number (API v3 and above), make
         * sure it matches the API version we used to fetch the report.
         *
         * For API v3 and up, this field MUST be in the report.
         */

        if (reportObj.hasKey("version")) {
            unsigned int rversion = (unsigned int)reportObj["version"].ToInt();
            if (_iasVersion != rversion) {
                cerr << "KmServer : Report version " << rversion << " does not match API version " << _iasVersion << endl;
                messages.clear();
                return false;
            }
        }

        memset(msg4, 0, sizeof(ra_msg4_t));

        if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
            msg4->status = true;
        } else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
            msg4->status = true;
        } else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
            msg4->status = true;
        } else {
            msg4->status = false;
        }
    }
    messages.clear();
    return true;
}
enclaveSession* kmServer::authkm()
{
    enclaveSession* ans = new enclaveSession();
    sgx_msg01_t msg01;
    sgx_ra_msg2_t msg2;
    ra_msg4_t msg4;

    char msg01Buffer[SGX_MESSAGE_MAX_SIZE];
    int msg01RecvSize;
    if (!raSecurityChannel_->recv(sslConnection_, msg01Buffer, msg01RecvSize)) {
        cerr << "KmServer : error socket reading msg01" << endl;
        return nullptr;
    }
    memcpy(&msg01, msg01Buffer, sizeof(msg01));
    if (!this->process_msg01(ans, msg01, msg2)) {
        cerr << "KmServer : error msg01" << endl;
        return nullptr;
    }

    int msg2SendSize = sizeof(msg2) + msg2.sig_rl_size;
    char msg2Buffer[msg2SendSize];
    memcpy(msg2Buffer, &msg2, sizeof(msg2) + msg2.sig_rl_size);
    if (!raSecurityChannel_->send(sslConnection_, msg2Buffer, msg2SendSize)) {
        cerr << "KmServer : error socket writing msg2" << endl;
        return nullptr;
    }

    int msg3RecvSize;
    char msg3Buffer[SGX_MESSAGE_MAX_SIZE];
    if (!raSecurityChannel_->recv(sslConnection_, msg3Buffer, msg3RecvSize)) {
        cerr << "KmServer : error msg01" << endl;
        return nullptr;
    }
    uint32_t quote_size = msg3RecvSize - sizeof(sgx_ra_msg3_t);
    string msg3Str((char*)msg3Buffer, msg3RecvSize);
    if (!this->process_msg3(ans, (sgx_ra_msg3_t*)msg3Str.c_str(), msg4, quote_size)) {
        cerr << "KmServer : error msg3" << endl;
        return nullptr;
    }

    int msg4SendSize = sizeof(msg4);
    char msg4Buffer[SGX_MESSAGE_MAX_SIZE];
    memcpy(msg4Buffer, &msg4, sizeof(msg4));
    if (!raSecurityChannel_->send(sslConnection_, msg4Buffer, msg4SendSize)) {
        cerr << "KmServer : error socket writing msg4" << endl;
        return nullptr;
    }

    return ans;
}