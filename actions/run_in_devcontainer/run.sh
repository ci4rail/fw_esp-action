#!/usr/bin/env bash
# $1 = image
# $2 = command

image=$1
command=$2

docker run \
    -u $(id -u):$(id -g) \
    --rm \
    -v $PWD:/workspace \
    -w /workspace \
    ${image} \
    bash -c '\
        groupadd -g "$(id -g)" hostgrp && \
        useradd -M -s /bin/bash -u "$(id -u)" -g hostgrp hostusr && \
        mkdir -p /home/hostusr && chown hostusr:hostgrp /home/hostusr && \
        source /opt/esp/idf/export.sh && \
        ${command}'