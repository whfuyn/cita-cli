#!/bin/bash
CITA_CLI_RELEASE_VERSION=$(git describe --tags "$(git rev-list --tags --max-count=1)")
cd ./docker/release/ || exit

docker build . -t "$CITA_CLI_REPOSITORY_NAME":"$CITA_CLI_RELEASE_VERSION"
cat "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
docker push "$CITA_CLI_REPOSITORY_NAME":"$CITA_CLI_RELEASE_VERSION"
