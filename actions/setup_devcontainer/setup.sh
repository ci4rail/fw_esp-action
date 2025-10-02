#!/usr/bin/env bash

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <image> <uid> <gid> <container-name>"
    exit 1
fi

image=$1
uid=$2
gid=$3
container_name=$4


set -x

docker run --name ${container_name} -d --entrypoint tail \
 -v $PWD:/workspace \
 -v /runner:/runner \
 -w /workspace \
 ${image} \
 -f /dev/null

echo "UID=${uid} GID=${gid}"

# generate user and group inside container with same uid/gid as host user
# Will fail if the group or user already exists, which is ok
docker exec ${container_name} bash -c "\
    groupadd -g "$gid" hostgrp && \
    useradd -M -s /bin/bash -u "$uid" -g hostgrp hostusr && \
    mkdir -p /home/hostusr && chown hostusr:hostgrp /home/hostusr && chown -R hostusr:hostgrp /opt/esp/idf"