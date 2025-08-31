#!/usr/bin/env bash

# Arguments:
# $1: binary file to sign

set -x
set -e
set -o pipefail

binary_file=$1

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <binary_file> <key_ids>"
    exit 1
fi

mapfile -t KEYS < <(printf '%s\n' "$key_ids" | tr -d '\r' | sed '/^[[:space:]]*$/d')

append_opt=""

num_keys=$(ls ${binary_file}-signature-* 2>/dev/null | wc -l)
echo "Found $num_keys signatures"

for (( i=0; i<num_keys; i++ )); do
    pubfile=${binary_file}-pub-${i}.pem
    sig_file=${binary_file}-signature-$i

    espsecure.py sign_data --version 2 \
    --pub-key $pubfile \
    --signature $sig_file \
    $append_opt \
    -- ${binary_file}
    
    espsecure.py verify_signature --version 2 --keyfile $pubfile ${binary_file}

    append_opt="--append_signatures"
done


