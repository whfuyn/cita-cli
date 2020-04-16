#!/bin/bash
CITA_CLI_RELEASE_VERSION=$(git describe --tags "$(git rev-list --tags --max-count=1)")
cd ./cita-cli
cargo install --no-default-features --features openssl --path . --force
cd ../docker/release
tar -zcf cita-cli-x86_64-mac-osx-tls-"$CITA_CLI_RELEASE_VERSION".tar.gz $HOME/.cargo/bin/cita-cli
