#src/server
add_library(dataSR STATIC dataSR.cpp)
add_library(dedupCore STATIC dedupCore.cpp)
add_library(storage STATIC storageCore.cpp)

add_executable(server-sgx ServerMain.cpp)
target_link_libraries(server-sgx ${SERVER_OBJ} ${LINK_OBJ})
