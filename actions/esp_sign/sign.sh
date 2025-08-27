#!/usr/bin/env bash

# Arguments:
# $1: binary file to sign
# $2: num keys
# $3: key id base

set -x
set -e
set -o pipefail

which az

binary_file=$1
num_keys=$2
key_id_base=$3

if [ -z "$binary_file" ] || [ -z "$num_keys" ] || [ -z "$key_id_base" ]; then
    echo "Error: Missing required arguments"
    exit 1
fi


# signing will be done in the .signed file
cp $binary_file $binary_file.signed

append_opt=""

for (( i=0; i<num_keys; i++ )); do
    if [ "$num_keys" -gt 1 ]; then
        key_id="${key_id_base}$i"
    else
        key_id="${key_id_base}"
    fi

    espsecure.py sign_data --version 2 \
    --pub-key $(basename $key_id)-pub.pem \
    --signature ${binary_file}-signature-$i \
    $append_opt \
    -- ${binary_file}.signed && \
    
    espsecure.py verify_signature --version 2 --keyfile $(basename $key_id)-pub.pem ${binary_file}.signed

    append_opt="--append_signatures"
done

cp $binary_file.signed $binary_file
echo "signed_binary_path=$binary_file" >> "$GITHUB_OUTPUT"
