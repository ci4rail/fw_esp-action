#!/usr/bin/env bash
# Use az keyvault to sign the digest of a binary file
# run in the github runner (not devcontainer)
# generates
#
# $binary_file-signature-0
# $binary_file-signature-1
# ...
# And the public key for each key
# $binary_file-0-pub.pem

# Arguments:
# $1: binary file to sign
# $2: key ids, newline separated

set -x
set -e
set -o pipefail

# check number of args
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <binary_file> <key_ids>"
    exit 1
fi

binary_file=$1
key_ids=$2

mapfile -t KEYS < <(printf '%s\n' "$key_ids" | tr -d '\r' | sed '/^[[:space:]]*$/d')

digest=$(openssl dgst -sha256 -binary ${binary_file} | base64 -w0)

for (( i=0; i<${#KEYS[@]}; i++ )); do
    key_id="${KEYS[$i]}"
    echo "Signing with key: $key_id"

    SIG=$(az keyvault key sign \
    --id "$key_id" \
    --algorithm PS256 \
    --digest "$digest" --query signature -o tsv)

    sig_file=${binary_file}-signature-$i
    echo "$SIG"| base64 -d > $sig_file

    if [ "$(wc -c < "$sig_file")" -ne 384 ]; then
        echo "Unexpected RSA signature length (expected 384 bytes)" >&2
        exit 1
    fi

    # download public key
    pubfile=${binary_file}-pub-${i}.pem
    rm -f "$pubfile"
    az keyvault key download --id "$key_id" --file "$pubfile"
done