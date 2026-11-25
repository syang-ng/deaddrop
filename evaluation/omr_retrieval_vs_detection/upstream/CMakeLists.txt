# The upstream DoS-PerfOMR demo, built from the overlay that build.sh assembles in build/src,
# with the same libraries and flags as omr-server/CMakeLists.txt.
cmake_minimum_required(VERSION 3.13)
project(omr_upstream CXX)
set(CMAKE_CXX_STANDARD 11)

get_filename_component(OMR_SERVER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../omr-server" ABSOLUTE)
set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/build/src")

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

link_directories(${PALISADE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
set(CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS})
link_libraries(${PALISADE_SHARED_LIBRARIES})

add_executable(omr_upstream ${SRC}/main.cpp)
target_link_libraries(omr_upstream Threads::Threads SEAL::seal ntl m gmp OpenSSL::Crypto)
