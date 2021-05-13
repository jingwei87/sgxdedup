//
// Created by a on 3/19/19.
//

#ifndef SGXDEDUP_KMSERVER_HPP
#define SGXDEDUP_KMSERVER_HPP

#include "../../../include/configure.hpp"
#include "../../../include/cryptoPrimitive.hpp"
#include "../../../include/messageQueue.hpp"
#include "../../../include/protocol.hpp"
#include "../../../include/ssl.hpp"
#include "base64.h"
#include "byteorder.h"
#include "crypto.h"
#include "enclaveSession.hpp"
#include "iasrequest.h"
#include "json.hpp"
#include "sgx_quote.h"
#include <iostream>

#define CA_BUNDLE "/etc/ssl/certs/ca-certificates.crt"
#define IAS_SIGNING_CA_FILE_KM "key/AttestationReportSigningCACert_km.pem"
#define IAS_CERT_FILE "key/iasclient.crt"
#define IAS_CLIENT_KEY "key/iasclient.pem"

//sp private key
static const unsigned char def_service_private_key_km[32] = {
    0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
    0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
    0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
    0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

class kmServer {
private:
    typedef struct config_struct {
        sgx_spid_t spid;
        unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
        unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
        uint16_t quote_type;
        EVP_PKEY* service_private_key;
        char* proxy_server;
        char* ca_bundle;
        char* user_agent;
        unsigned int proxy_port;
        unsigned char kdk[16];
        X509_STORE* store;
        X509* signing_ca;
        unsigned int apiver;
        int strict_trust;
        sgx_measurement_t req_mrsigner;
        sgx_prod_id_t req_isv_product_id;
        sgx_isv_svn_t min_isvsvn;
        int allow_debug_enclave;
    } config_t;

    IAS_Connection* _ias;
    X509* _signing_ca;
    X509_STORE* _store;
    CryptoPrimitive _crypto;
    sgx_spid_t _spid;
    uint16_t _quote_type;
    EVP_PKEY* _service_private_key;
    uint16_t _iasVersion;
    bool process_msg01(enclaveSession* session, sgx_msg01_t& msg01, sgx_ra_msg2_t& msg2);
    bool process_msg3(enclaveSession* session, sgx_ra_msg3_t* msg3, ra_msg4_t& msg4, uint32_t quote_sz);
    bool derive_kdk(EVP_PKEY* Gb, unsigned char kdk[16], sgx_ec256_public_t g_a);
    bool get_sigrl(sgx_epid_group_id_t gid, char* sig_rl, uint32_t* sig_rl_size);
    bool get_attestation_report(const char* b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t* msg4);
    ssl* raSecurityChannel_;
    SSL* sslConnection_;

public:
    kmServer(ssl* raSecurityChannel, SSL* sslConnection);
    enclaveSession* authkm();
};

#endif //SGXDEDUP_KMSERVER_HPP
