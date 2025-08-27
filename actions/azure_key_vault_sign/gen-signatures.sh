#!/usr/bin/env bash
# Use az keyvault to sign the digest of a binary file
# run in the github runner (not devcontainer)
# generates
#
# $binary_file-${signature_suffix}signature-0
# $binary_file-${signature_suffix}signature-1
# ...
# And the public key for each key
# $binary_file-${signature_suffix}pub-0.pem

# Arguments:
# $1: binary file to sign
# $2: num keys
# $3: key id base
# $4: signature suffix

set -x
set -e
set -o pipefail

binary_file=$1
num_keys=$2
key_id_base=$3
signature_suffix=$4

if [ -z "$binary_file" ] || [ -z "$num_keys" ] || [ -z "$key_id_base" ] || [ -z "$signature_suffix" ]; then
    echo "Error: Missing required arguments"
    exit 1
fi

digest=$(openssl dgst -sha256 -binary ${binary_file} | base64 -w0)

for (( i=0; i<num_keys; i++ )); do
    key_id="${key_id_base}$i"

    SIG=$(az keyvault key sign \
    --id "$key_id" \
    --algorithm PS256 \
    --digest "$digest" --query signature -o tsv)

    echo "$SIG"| base64 -d > ${binary_file}-${signature_suffix}$i

    if [ "$(wc -c < "${binary_file}-${signature_suffix}$i")" -ne 384 ]; then
        echo "Unexpected RSA signature length (expected 384 bytes)" >&2
        exit 1
    fi

    # download public key
    az keyvault key download --id "$key_id" --file "${binary_file}-${signature_suffix}pub-${i}.pem"
done