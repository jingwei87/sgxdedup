#src/enclave/src

#add_library(powClient powClient.cpp)
#target_link_libraries(powClient enclave_untrusted ${SGX_U_LIBRARY_OBJ} sender)

add_library(powServer powServer.cpp)
add_library(kmServer kmServer.cpp)

target_link_libraries(powServer base64 sgx_crypto iasrequest hexutil byteorder agent_wget POW_json sgxErrorSupport common logfile)
target_link_libraries(kmServer base64 sgx_crypto iasrequest hexutil byteorder agent_wget POW_json sgxErrorSupport common logfile)