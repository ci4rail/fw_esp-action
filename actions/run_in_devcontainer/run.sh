#!/usr/bin/env bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <run_id> <command>"
    exit 1
fi

run_id=$1
command=$2
container_name=esp-devc-${run_id}

docker exec -u $(id -u):$(id -g) ${container_name} bash -c "source /opt/esp/idf/export.sh && ${command}"
