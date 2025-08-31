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
 --name ${container_name} \
 -v $PWD:/workspace \
 -v /runner:/runner \
 -w /workspace \
 ${image} \
 -f /dev/null

echo "UID=${uid} GID=${gid}"

docker exec ${container_name} bash -c "\
    groupadd -g "$gid" hostgrp && \
    useradd -M -s /bin/bash -u "$uid" -g hostgrp hostusr && \
    mkdir -p /home/hostusr && chown hostusr:hostgrp /home/hostusr"