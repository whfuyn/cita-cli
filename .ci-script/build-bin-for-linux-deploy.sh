#!/bin/bash
# First, install musl-gcc, default on /usr/local/musl
wget https://www.musl-libc.org/releases/musl-1.1.19.tar.gz
tar -zxf musl-1.1.19.tar.gz
cd musl-1.1.19/
./configure && make && sudo make install
sudo ln -sf /usr/local/musl/bin/musl-gcc /usr/local/bin/musl-gcc

# Second, add x86_64-unknown-linux-musl toolchain
rustup target add x86_64-unknown-linux-musl

# Third, build，generate cita-cli
cd ../cita-cli
cargo install --target x86_64-unknown-linux-musl --path . --force
cd ../docker/release
cp $HOME/.cargo/bin/cita-cli ./
tar -zcf cita-cli-x86_64-musl-tls-"$TRAVIS_TAG".tar.gz cita-cli
