#!/usr/bin/env bash

# Arguments:
# $1: binary file to sign
# $2: num keys
# $3: key id base

binary_file=$1
num_keys=$2
key_id_base=$3

if [ -z "$binary_file" ] || [ -z "$num_keys" ] || [ -z "$key_id_base" ]; then
    echo "Error: Missing required arguments"
    exit 1
fi

sign_binary_with_esp_secure()
{
    binary_file=$1
    append_opt=$2
    key_id=$3
    # sign and verify signature
    # run in esp-idf python environment
    source /opt/esp/idf/export.sh

    espsecure.py sign_data --version 2 \
    --pub-key $(basename $key_id)-pub.pem \
    --signature $binary_file-signature-$i \
    $append_opt \
    -- $binary_file.signed && \
    espsecure.py verify_signature --version 2 --keyfile $(basename $key_id)-pub.pem $binary_file.signed
}

digest=$(openssl dgst -sha256 -binary $binary_file | base64 -w0)

# signing will be done in the .signed file
cp $binary_file $binary_file.signed

append_opt=""

for (( i=0; i<num_keys; i++ )); do
    if [ "$num_keys" -gt 1 ]; then
    KEY_ID="${key_id_base}$i"
    else
    KEY_ID="${key_id_base}"
    fi
    SIG=$(az keyvault key sign \
    --id "$KEY_ID" \
    --algorithm PS256 \
    --digest "$digest" --query signature -o tsv)
    echo "$SIG"| base64 -d > $binary_file-signature-$i

    if [ "$(wc -c < "$binary_file-signature-$i")" -ne 384 ]; then
        echo "Unexpected RSA signature length (expected 384 bytes)" >&2
        exit 1
    fi

    # download public key
    rm -f $(basename "$KEY_ID")-pub.pem
    az keyvault key download --id "$KEY_ID" --file $(basename "$KEY_ID")-pub.pem

    $(sign_binary_with_esp_secure $binary_file $append_opt $KEY_ID)

    append_opt="--append_signatures"
done
cp $binary_file.signed $binary_file
echo "signed_binary_path=$binary_file" >> "$GITHUB_OUTPUT"
