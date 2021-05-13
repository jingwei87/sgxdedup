#/
set(CMAKE_MODULE_PATH /usr/share/cmake-3.10/Modules/)
list(APPEND CMAKE_MODULE_PATH ${PATH_TO_FindSGX.cmake_FILE})
find_package(SGX REQUIRED)

find_package(Boost 1.36.0 REQUIRED COMPONENTS thread system serialization)
if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  link_directories(${BOOST_LIBRARY_DIR})
endif()

set(OPENSSL_INCLUDE_PATH /usr/include/)
set(OPENSSL_LIBRARY_PATH /usr/lib/x86_64-linux-gnu)

set(SGX_INCLUDE_PATH /opt/intel/sgxsdk/include)
set(ENCLAVE_INCLUDE_PATH enclave/include)

include_directories(${SGX_INCLUDE_PATH} ${ENCLAVE_INCLUDE_PATH} ../include)
link_directories(util)

set(BOOST_LIBRARY_OBJ boost_thread boost_system boost_serialization)
set(SYSTEM_LIBRARY_OBJ pthread rt dl)
set(OPENSSL_LIBRARY_OBJ ssl crypto)
set(LEVELDB_LIBRARY_OBJ pthread leveldb)
set(UTIL_OBJ configure cryptoPrimitive SSL_TLS database)

set(LINK_OBJ ${UTIL_OBJ} ${OPENSSL_LIBRARY_OBJ} ${LEVELDB_LIBRARY_OBJ} ${BOOST_LIBRARY_OBJ} ${UTIL_OBJ} ${SYSTEM_LIBRARY_OBJ})

set(CLIENT_OBJ chunker fingerprinter keyClient encoder powClient sender recvDecode  retriever)
set(SERVER_OBJ dataSR  dedupCore powServer storage kmServer) 
set(KEYSERVER_OBJ keyServer kmClient sgxErrorSupport)

#-fno-builtin-memset

set (CMAKE_SYSTEM_NAME Linux )
if (NOT CMAKE_BUILD_TYPE)
   set (CMAKE_BUILD_TYPE "Release")
   message (
      STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}"
   )
endif ()

set(CMAKE_C_FLAGS_DEBUG "-Wall -std=c1x -g -ggdb -g2") 
set(CMAKE_CXX_FLAGS_DEBUG "-Wall -std=c++17 -g -ggdb -g2 -fno-omit-frame-pointer -fsanitize=leak")
set(CMAKE_C_FLAGS_RELEASE "-O3 -std=c1x") 
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -std=c++11")
set(CMAKE_MODULE_PATH /usr/share/cmake-3.10/Modules/)

# SET (CMAKE_C_COMPILER             "/usr/bin/clang")
# SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
# SET (CMAKE_AR      "/usr/bin/llvm-ar")
# SET (CMAKE_LINKER  "/usr/bin/llvm-ld")
# SET (CMAKE_NM      "/usr/bin/llvm-nm")
# SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
# SET (CMAKE_RANLIB  "/usr/bin/llvm-ranlib")

add_subdirectory(enclave)
add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(keymanage)
add_subdirectory(util)