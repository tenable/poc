#! /usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
set -e
pushd openssl-1.0.2

C_INCLUDE_PATH=/usr/lib/musl/include CC=musl-gcc ./Configure no-shared no-zlib disable-ec enable-rsa enable-md5 no-ssl2 no-ssl3 no-threads no-krb5 no-asm no-hw no-dso no-engine no-dtls1 no-idea no-comp no-err no-psk no-srp linux-x86_64-musl --prefix=$(realpath "$SCRIPT_DIR"/opt) --openssldir=$(realpath "$SCRIPT_DIR"/opt) 

make depend

make -j $(nproc) build_crypto

cp -v libcrypto.a ..

popd
