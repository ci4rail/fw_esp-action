#!/usr/bin/env bash
# $1 = command

command=$1
CONTAINER_NAME=esp-devc

docker exec -u $(id -u):$(id -g) ${CONTAINER_NAME} bash -c "source /opt/esp/idf/export.sh && ${command}"
