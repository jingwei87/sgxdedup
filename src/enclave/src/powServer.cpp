#include "powServer.hpp"
#include "sgx_uae_service.h"
//./sp -s 928A6B0E3CDDAD56EB3BADAA3B63F71F -A ./client.crt
// -C ./client.crt --ias-cert-key=./client.pem -x -d -v
// -A AttestationReportSigningCACert.pem -C client.crt
// -s 797F0D90EE75B24B554A73AB01FD3335 -Y client.pem

void PRINT_BYTE_ARRAY_POW_SERVER(
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

void powServer::closeSession(int fd)
{
    sessions.erase(fd);
}

powServer::powServer()
{
    cryptoObj_ = new CryptoPrimitive();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (!cert_load_file(&_signing_ca, IAS_SIGNING_CA_FILE)) {
        cerr << "PowServer : can not load IAS Signing Cert CA" << endl;
        exit(1);
    }

    _store = cert_init_ca(_signing_ca);
    if (_store == nullptr) {
        cerr << "PowServer : can not init cert file" << endl;
        exit(1);
    }

    string spid = config.getPOWSPID();
    if (spid.length() != 32) {
        cerr << "PowServer : SPID must be 32-byte hex string" << endl;
        exit(1);
    }

    from_hexstring((unsigned char*)&_spid, (const void*)&spid[0], 16);
    _ias = new IAS_Connection(
        config.getPOWIASServerType(),
        0,
        (char*)(config.getPOWPriSubscriptionKey().c_str()),
        (char*)(config.getPOWSecSubscriptionKey().c_str()));
    _ias->agent("wget");
    // _ias->client_cert(IAS_CERT_FILE, "PEM");
    // _ias->client_key(IAS_CLIENT_KEY, nullptr);
    _ias->proxy_mode(IAS_PROXY_NONE);
    _ias->cert_store(_store);
    _ias->ca_bundle(CA_BUNDLE);

    _quote_type = config.getPOWQuoteType();
    _service_private_key = key_private_from_bytes(def_service_private_key);
    _iasVersion = config.getPOWIASVersion();
}

powServer::~powServer()
{
    auto it = sessions.begin();
    while (it != sessions.end()) {
        delete it->second;
        it++;
    }
    sessions.clear();
    free(_service_private_key);
    delete cryptoObj_;
}
bool powServer::process_msg01(int fd, sgx_msg01_t& msg01, sgx_ra_msg2_t& msg2)
{
    enclaveSession* current = new enclaveSession();
    sessions.insert(make_pair(fd, current));

    EVP_PKEY* Gb;
    unsigned char digest[32], r[32], s[32], gb_ga[128];

    if (msg01.msg0_extended_epid_group_id != 0) {
        cerr << "PowServer : msg0 Extended Epid Group ID is not zero.  Exiting.\n";
        return false;
    }

    memcpy(&current->msg1, &msg01.msg1, sizeof(sgx_ra_msg1_t));

    Gb = key_generate();
    if (Gb == nullptr) {
        cerr << "PowServer : can not create session key\n";
        free(Gb);
        return false;
    }

    if (!derive_kdk(Gb, current->kdk, msg01.msg1.g_a)) {
        cerr << "PowServer : can not derive KDK\n";
        free(Gb);
        return false;
    }

    cmac128(current->kdk, (unsigned char*)("\x01SMK\x00\x80\x00"), 7,
        current->smk);

    //build msg2
    memset(&msg2, 0, sizeof(sgx_ra_msg2_t));

    key_to_sgx_ec256(&msg2.g_b, Gb);
    memcpy(&msg2.spid, &_spid, sizeof(sgx_spid_t));
    msg2.quote_type = _quote_type;
    msg2.kdf_id = 1;

    if (!get_sigrl(msg01.msg1.gid, (char*)&msg2.sig_rl, &msg2.sig_rl_size)) {
        cerr << "PowServer : can not retrieve sigrl form ias server\n";
        free(Gb);
        return false;
    }

    memcpy(gb_ga, &msg2.g_b, 64);
    memcpy(current->g_b, &msg2.g_b, 64);

    memcpy(&gb_ga[64], &current->msg1.g_a, 64);
    memcpy(current->g_a, &current->msg1.g_a, 64);

    ecdsa_sign(gb_ga, 128, _service_private_key, r, s, digest);
    reverse_bytes(&msg2.sign_gb_ga.x, r, 32);
    reverse_bytes(&msg2.sign_gb_ga.y, s, 32);

    cmac128(current->smk, (unsigned char*)&msg2, 148, (unsigned char*)&msg2.mac);
    free(Gb);
    return true;
}

bool powServer::derive_kdk(EVP_PKEY* Gb, unsigned char* kdk, sgx_ec256_public_t g_a)
{
    unsigned char* Gab_x;
    unsigned char cmacKey[16];
    size_t len;
    EVP_PKEY* Ga;
    Ga = key_from_sgx_ec256(&g_a);
    if (Ga == nullptr) {
        cerr << "PowServer : can not get ga from msg1\n";
        return false;
    }
    Gab_x = key_shared_secret(Gb, Ga, &len);
    if (Gab_x == nullptr) {
        cerr << "PowServer : can not get shared secret\n";
        return false;
    }
    reverse_bytes(Gab_x, Gab_x, len);

    memset(cmacKey, 0, sizeof(cmacKey));
    cmac128(cmacKey, Gab_x, len, kdk);
    return true;
}

bool powServer::get_sigrl(uint8_t* gid, char* sig_rl, uint32_t* sig_rl_size)
{
    IAS_Request* req = nullptr;

    req = new IAS_Request(_ias, _iasVersion);
    if (req == nullptr) {
        cerr << "PowServer : can not make ias request\n";
        return false;
    }
    string sigrlstr;
    if (req->sigrl(*(uint32_t*)gid, sigrlstr) != IAS_OK) {
        cerr << "PowServer : ias get sigrl error\n";
        return false;
    }
    memcpy(sig_rl, &sigrlstr[0], sigrlstr.length());
    if (sig_rl == nullptr) {
        return false;
    }
    *sig_rl_size = (uint32_t)sigrlstr.length();
    return true;
}

bool powServer::process_msg3(enclaveSession* current, sgx_ra_msg3_t* msg3,
    ra_msg4_t& msg4, uint32_t quote_sz)
{

    if (CRYPTO_memcmp(&msg3->g_a, &current->msg1.g_a, sizeof(sgx_ec256_public_t))) {
        cerr << "PowServer : msg1.ga != msg3.ga\n";
        return false;
    }
    sgx_mac_t msgMAC;
    cmac128(current->smk, (unsigned char*)&msg3->g_a, sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_sz, (unsigned char*)msgMAC);
    if (CRYPTO_memcmp(msg3->mac, msgMAC, sizeof(sgx_mac_t))) {
        cerr << "PowServer : broken msg3 from client\n";
        return false;
    }
    char* b64quote;
    b64quote = base64_encode((char*)&msg3->quote, quote_sz);
    sgx_quote_t* q;
    q = (sgx_quote_t*)msg3->quote;
    if (memcmp(current->msg1.gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t))) {
        cerr << "PowServer : Attestation failed. Differ gid\n";
        return false;
    }
    if (get_attestation_report(b64quote, msg3->ps_sec_prop, &msg4)) {
        free(b64quote);
        cerr << "PowServer : Get Attestation report success\n";
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

            cerr << "PowServer : Report verification failed.\n";
            return false;
        }
        // temp ---- msg4 maul setting
        msg4.status = true;
        if (msg4.status) {
            cmac128(current->kdk, (unsigned char*)("\x01MK\x00\x80\x00"),
                6, current->mk);
            cmac128(current->kdk, (unsigned char*)("\x01SK\x00\x80\x00"),
                6, current->sk);

            current->enclaveTrusted = true;
            return true;
        } else {
            cout << "PowServer : set client session key error" << endl;
            return false;
        }
    } else {
        free(b64quote);
        cerr << "PowServer : Remote Attestation Failed" << endl;
        return false;
    }
}

bool powServer::get_attestation_report(const char* b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t* msg4)
{
    IAS_Request* req = nullptr;
    map<string, string> payload;
    vector<string> messages;
    ias_error_t status;
    string content;

    req = new IAS_Request(_ias, (uint16_t)_iasVersion);
    if (req == nullptr) {
        cerr << "PowServer : Exception while creating IAS request object\n";
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
                cerr << "PowServer : Report version " << rversion << " does not match API version " << _iasVersion << endl;
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
    return true;
}

bool powServer::process_signedHash(enclaveSession* session, u_char* mac, u_char* hashList, int chunkNumber)
{
    u_char serverMac[16];
    cryptoObj_->cmac128(hashList, chunkNumber, serverMac, session->sk, 16);
    if (memcmp(mac, serverMac, 16) == 0) {
        return true;
    } else {
        cerr << "PowServer : client signature unvalid, client mac = " << endl;
        PRINT_BYTE_ARRAY_POW_SERVER(stderr, mac, 16);
        cerr << "\t server mac = " << endl;
        PRINT_BYTE_ARRAY_POW_SERVER(stderr, serverMac, 16);
        return false;
    }
}
