# Build environment (image omr-env:focal) for omr-server and the evaluation harnesses, following omr-server/README.md on Ubuntu 20.04.
# Dependencies are installed into /opt/omr. The repo itself is mounted at run time, not copied in.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

# README: build-essential, autoconf, cmake, libgmp3-dev, libntl-dev (11.4.3-1build1 on focal), unzip.
# git and ca-certificates are needed for the clones and for SEAL's FetchContent.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf cmake libgmp3-dev libntl-dev unzip git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg-query -W -f='${Package} ${Version}\n' build-essential cmake libntl-dev libgmp3-dev g++ > /opt/apt-versions.txt

ARG PREFIX=/opt/omr
ARG JOBS=16
WORKDIR /src

# PALISADE v1.11.3 (unit tests, examples and benchmarks off: they are not installed and not needed)
RUN git clone -b v1.11.3 https://gitlab.com/palisade/palisade-release \
    && cd palisade-release && echo "palisade $(git rev-parse HEAD)" >> /opt/src-versions.txt \
    && mkdir build && cd build \
    && cmake .. -DCMAKE_INSTALL_PREFIX=${PREFIX} \
               -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
    && make -j${JOBS} && make install \
    && cd .. && rm -rf build

# OpenSSL 1.1.1 (branch OpenSSL_1_1_1-stable), for the plain AES functions
RUN git clone --depth 1 -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl \
    && cd openssl && echo "openssl $(git rev-parse HEAD)" >> /opt/src-versions.txt \
    && ./config --prefix=${PREFIX} && make -j${JOBS} && make install_sw \
    && make clean

# SEAL 4.1 fork used by PerfOMR, with Intel HEXL as in the README
RUN git clone https://github.com/wyunhao/SEAL \
    && cd SEAL && echo "seal $(git rev-parse HEAD)" >> /opt/src-versions.txt \
    && cmake -S . -B build -DCMAKE_INSTALL_PREFIX=${PREFIX} -DSEAL_USE_INTEL_HEXL=ON \
    && cmake --build build -j${JOBS} && cmake --install build \
    && rm -rf build

ENV LD_LIBRARY_PATH=${PREFIX}/lib
ENV HOME=/tmp
