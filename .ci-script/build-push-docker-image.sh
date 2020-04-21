#!/bin/bash
cd ./docker/release/ || exit

docker build . -t "$CITA_CLI_REPOSITORY_NAME":"$TRAVIS_TAG"
cat "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
docker push "$CITA_CLI_REPOSITORY_NAME":"$TRAVIS_TAG"
