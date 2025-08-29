#!/usr/bin/env bash

# $1 = image

image=$1
CONTAINER_NAME=esp-devc

 docker run --name devc -d --entrypoint tail \
 --name ${CONTAINER_NAME} \
 -v $PWD:/workspace \
 -w /workspace \
 ${image} \
 -f /dev/null

 docker exec ${CONTAINER_NAME} bash -c '
    groupadd -g "$(id -g)" hostgrp && \
    useradd -M -s /bin/bash -u "$(id -u)" -g hostgrp hostusr && \
    mkdir -p /home/hostusr && chown hostusr:hostgrp /home/hostusr'