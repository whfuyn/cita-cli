#!/bin/bash
cd ./cita-cli
cargo install --no-default-features --features openssl --path . --force
cd ../docker/release
tar -zcf cita-cli-x86_64-mac-osx-tls-"$TRAVIS_TAG".tar.gz $HOME/.cargo/bin/cita-cli
