#!/usr/bin/env bash
# Use az keyvault to sign the digest of a binary file
# run in the github runner (not devcontainer)
# generates
#
# $binary_file${signature_suffix}-signature-0
# $binary_file${signature_suffix}-signature-1
# ...
# And the public key for each key
# $binary_file${signature_suffix}-pub-0.pem

# Arguments:
# $1: binary file to sign
# $2: num keys
# $3: key id base
# $4: signature suffix

set -x
set -e
set -o pipefail

# check number of args
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <binary_file> <num_keys> <key_id_base> <signature_suffix>"
    exit 1
fi

binary_file=$1
num_keys=$2
key_id_base=$3
signature_suffix=$4

digest=$(openssl dgst -sha256 -binary ${binary_file} | base64 -w0)

for (( i=0; i<num_keys; i++ )); do
    if [ "$num_keys" -gt 1 ]; then
        key_id="${key_id_base}$i"
    else 
        key_id="${key_id_base}"
    fi

    SIG=$(az keyvault key sign \
    --id "$key_id" \
    --algorithm PS256 \
    --digest "$digest" --query signature -o tsv)

    sig_file=${binary_file}${signature_suffix}-signature-$i
    echo "$SIG"| base64 -d > $sig_file

    if [ "$(wc -c < "$sig_file")" -ne 384 ]; then
        echo "Unexpected RSA signature length (expected 384 bytes)" >&2
        exit 1
    fi

    # download public key
    rm -f "${binary_file}${signature_suffix}-pub-${i}.pem"
    az keyvault key download --id "$key_id" --file "${binary_file}${signature_suffix}-pub-${i}.pem"
done