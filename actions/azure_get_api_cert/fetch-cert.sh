#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <azure_secret_id> <output_prefix> <github_output>" >&2
    exit 1
fi

secret_id=$1
output_prefix=$2
github_output=$3

if [ -z "$secret_id" ]; then
    echo "azure_secret_id must not be empty" >&2
    exit 1
fi

if [ -z "$output_prefix" ]; then
    echo "output_prefix must not be empty" >&2
    exit 1
fi

output_dir=$(dirname "$output_prefix")
mkdir -p "$output_dir"

cert_path="${output_prefix}.crt"
key_path="${output_prefix}.key"

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

tmp_pfx_b64="${tmp_dir}/cert.pfx.b64"
tmp_pfx="${tmp_dir}/cert.pfx"

az keyvault secret show \
    --id "$secret_id" \
    --query value \
    -o tsv > "$tmp_pfx_b64"

base64 -d "$tmp_pfx_b64" > "$tmp_pfx"

openssl pkcs12 \
    -in "$tmp_pfx" \
    -clcerts \
    -nokeys \
    -passin pass: \
    -out "$cert_path"

openssl pkcs12 \
    -in "$tmp_pfx" \
    -nocerts \
    -nodes \
    -passin pass: \
    -out "$key_path"

chmod 600 "$key_path"

{
    echo "cert-path=$cert_path"
    echo "key-path=$key_path"
} >> "$github_output"
