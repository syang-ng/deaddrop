# Builds omr_bench against the vendored OMR server headers with the same libraries and flags as
# omr-server/CMakeLists.txt. NUM_TRANSACTIONS sets the board size compiled into API.h.
cmake_minimum_required(VERSION 3.13)
project(omr_bench CXX)
set(CMAKE_CXX_STANDARD 11)

set(NUM_TRANSACTIONS 32768 CACHE STRING "Board size N (multiple of 32768)")
get_filename_component(OMR_SERVER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../omr-server" ABSOLUTE)

find_package(Palisade REQUIRED)
find_package(SEAL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS})

include_directories(${OPENMP_INCLUDES})
include_directories(${PALISADE_INCLUDE})
include_directories(${PALISADE_INCLUDE}/third-party/include)
include_directories(${PALISADE_INCLUDE}/core)
include_directories(${PALISADE_INCLUDE}/pke)
include_directories(${OMR_SERVER_DIR}/include/palisade/core)
include_directories(${OMR_SERVER_DIR}/include/palisade)
include_directories(${OMR_SERVER_DIR})

link_directories(${PALISADE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
set(CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS})
link_libraries(${PALISADE_SHARED_LIBRARIES})

add_executable(omr_bench omr_bench.cpp)
target_compile_definitions(omr_bench PRIVATE DEADDROP_NUM_TRANSACTIONS=${NUM_TRANSACTIONS})
target_link_libraries(omr_bench Threads::Threads SEAL::seal ntl m gmp OpenSSL::Crypto)
