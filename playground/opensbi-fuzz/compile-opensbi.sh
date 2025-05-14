#!/bin/bash

CACHE_DIR="output/.cache"
mkdir -p $CACHE_DIR

TOOLCHAIN_IMAGE="opensbi-toolchain:latest"
if ! docker image inspect $TOOLCHAIN_IMAGE &>/dev/null; then
    cat > $CACHE_DIR/Dockerfile << EOF
FROM ubuntu:22.04
RUN apt update && \
    apt install -y make gcc-riscv64-linux-gnu curl lsb-release gnupg software-properties-common
RUN curl -sSL https://apt.llvm.org/llvm.sh | bash -s -- 18
RUN ln -sf /usr/bin/clang-18 /usr/bin/clang && \
    ln -sf /usr/bin/clang++-18 /usr/bin/clang++ && \
    ln -sf /usr/bin/lld-18 /usr/bin/lld && \
    ln -sf /usr/bin/ld.lld-18 /usr/bin/ld.lld && \
    ln -sf /usr/bin/llvm-ar-18 /usr/bin/llvm-ar && \
    ln -sf /usr/bin/llvm-objcopy-18 /usr/bin/llvm-objcopy
EOF
    docker build -t $TOOLCHAIN_IMAGE -f $CACHE_DIR/Dockerfile .
fi

CONTAINER_ID=$(docker run -d $TOOLCHAIN_IMAGE sleep infinity)

rm -rf ./output/opensbi/build

docker cp ./output/opensbi $CONTAINER_ID:/opensbi

docker exec $CONTAINER_ID bash -c "cd /opensbi && \
    ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- make PLATFORM=generic LLVM=1"

docker cp $CONTAINER_ID:/opensbi/build ./output/opensbi/build

(docker stop $CONTAINER_ID  && docker rm $CONTAINER_ID) > /dev/null &
