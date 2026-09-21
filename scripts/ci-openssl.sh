#!/usr/bin/env bash
# Independent test oracle only; this library is never linked into the package.
set -euo pipefail
prefix="${RUNNER_TEMP:?RUNNER_TEMP must be set}/post-quantum-openssl"
build="${RUNNER_TEMP}/post-quantum-openssl-source"
mkdir -p "$build"
cd "$build"
curl --fail --location --silent --show-error --output openssl-3.5.8.tar.gz \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz
printf '%s\n' 'a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2  openssl-3.5.8.tar.gz' | sha256sum --check --strict
tar -xzf openssl-3.5.8.tar.gz
cd openssl-3.5.8
./Configure shared no-tests --prefix="$prefix" --libdir=lib
make -j2
make install_sw
printf 'OPENSSL_LIBCRYPTO=%s/lib/libcrypto.so.3\n' "$prefix" >> "${GITHUB_ENV:?GITHUB_ENV must be set}"
