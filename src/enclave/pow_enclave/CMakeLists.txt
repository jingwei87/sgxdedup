# src/enclave/pow_enclave

set(SGXOPENSSL_INCLUDE_PATH /opt/intel/sgxssl/include)
set(SGXOPENSSL_LIBRARY_PATH /opt/intel/sgxssl/lib64)

set(EDL_SEARCH_PATHS /opt/intel/sgxsdk/include)
set(E_SRC pow_enclave.cpp)
set(LDS pow_enclave.lds)
set(EDL_SEARCH_PATHS ${SGXOPENSSL_INCLUDE_PATH} /opt/intel/sgxsdk/include)
set(SGXOPENSSL_OBJECTS  sgx_tsgxssl_crypto sgx_tsgxssl sgx_tstdc sgx_tcxx)

include_directories(${SGXOPENSSL_INCLUDE_PATH})
link_directories(${SGXOPENSSL_LIBRARY_PATH})


add_enclave_library(pow_enclave
                    SRCS ${E_SRC}
                    EDL pow_enclave.edl
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                    LDSCRIPT ${LDS})

enclave_sign(pow_enclave KEY pow_enclave_private.pem CONFIG pow_enclave.config.xml)


set(U_SRC ../src/powClient.cpp)
add_untrusted_library(powClient
                     STATIC
                     SRCS ${U_SRC}
                     EDL pow_enclave.edl
                     EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})