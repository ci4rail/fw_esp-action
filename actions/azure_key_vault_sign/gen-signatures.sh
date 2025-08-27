#!/usr/bin/env bash
# Use az keyvault to sign the digest of a binary file
# run in the github runner (not devcontainer)
# generates
#
# $binary_file-signature-0
# $binary_file-signature-1
# ...
# Or just 
# $binary_file-signature if num_keys==1
#
# And the public key for each key
# $(basename "$key_id"0)-pub.pem for each key

# Arguments:
# $1: binary file to sign
# $2: num keys
# $3: key id base

set -x
set -e
set -o pipefail

binary_file=$1
num_keys=$2
key_id_base=$3

if [ -z "$binary_file" ] || [ -z "$num_keys" ] || [ -z "$key_id_base" ]; then
    echo "Error: Missing required arguments"
    exit 1
fi

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
    
    echo "$SIG"| base64 -d > ${binary_file}-signature-$i

    if [ "$(wc -c < "${binary_file}-signature-$i")" -ne 384 ]; then
        echo "Unexpected RSA signature length (expected 384 bytes)" >&2
        exit 1
    fi

    # download public key
    rm -f $(basename "$key_id")-pub.pem
    az keyvault key download --id "$key_id" --file $(basename "$key_id")-pub.pem
done