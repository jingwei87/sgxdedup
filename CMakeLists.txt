cmake_minimum_required(VERSION 3.1)
project(SGXDEDUP)

set(CMAKE_CXX_STANDARD 11)

set(EXECUTABLE_OUTPUT_PATH ${SGXDEDUP_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${SGXDEDUP_SOURCE_DIR}/lib)

add_subdirectory(src)