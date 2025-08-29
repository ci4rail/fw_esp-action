#!/usr/bin/env bash

# $1 = image

image=$1
uid=$2
gid=$3
CONTAINER_NAME=esp-devc

docker rm -f ${CONTAINER_NAME}

docker run --name devc -d --entrypoint tail \
 --name ${CONTAINER_NAME} \
 -v $PWD:/workspace \
 -w /workspace \
 ${image} \
 -f /dev/null

echo "UID=${uid} GID=${gid}"

docker exec ${CONTAINER_NAME} bash -c '\
    groupadd -g "$gid" hostgrp && \
    useradd -M -s /bin/bash -u "$uid" -g hostgrp hostusr && \
    mkdir -p /home/hostusr && chown hostusr:hostgrp /home/hostusr'