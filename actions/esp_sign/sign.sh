#!/usr/bin/env bash

# Arguments:
# $1: binary file to sign
# $2: key ids, newline separated

set -x
set -e
set -o pipefail

binary_file=$1
key_ids=$2

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <binary_file> <key_ids>"
    exit 1
fi

mapfile -t KEYS < <(printf '%s\n' "$key_ids" | sed '/^[[:space:]]*$/d')

# signing will be done in the .signed file
cp $binary_file $binary_file.signed

append_opt=""

for (( i=0; i<${#KEYS[@]}; i++ )); do
    key_id="${KEYS[$i]}"

    pubfile=${binary_file}-pub-${i}.pem
    sig_file=${binary_file}-signature-$i

    espsecure.py sign_data --version 2 \
    --pub-key $pubfile \
    --signature $sig_file \
    $append_opt \
    -- ${binary_file}.signed && \

    espsecure.py verify_signature --version 2 --keyfile $pubfile ${binary_file}.signed

    append_opt="--append_signatures"
done

cp $binary_file.signed $binary_file

