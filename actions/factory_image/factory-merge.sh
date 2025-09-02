#!/usr/bin/env bash

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <chip> <build_dir> <final_app> <final_bl> <output_file>"
    exit 1
fi

set -e 

chip=$1
build_dir=$2
final_app=$3
bl_pattern=$4
output_file=$5

cd $build_dir

options_bl=$(grep -- --flash flash_bootloader_args)
options_project=$(grep -- --flash flash_project_args)

# check if both options are identical
if [ "$options_bl" != "$options_project" ]; then
    echo "Bootloader and project options are different"
    exit 1
fi

final_bl=$(find . -maxdepth 1 -type f -name "$bl_pattern" | head -n1)
if [ -z "$final_bl" ]; then
    echo "Bootloader file with pattern $bl_pattern not found"
    exit 1
fi

# go through flash_project_args.
# ignore lines starting with "--"
# other lines are "offset filename"
# extract the offset and filename
org_content=$(cat flash_bootloader_args flash_project_args)

merge_args=""
while read -r line; do
    if [[ "$line" == --* ]]; then
        continue
    fi
    offset=$(echo "$line" | awk '{print $1}')
    filename=$(echo "$line" | awk '{print $2}')
    offsets+=("$offset")

    if [[ $final_app == ${filename%.*}* ]]; then
        filename=("$final_app")
    elif [[ ${filename} == bootloader/* ]]; then
        filename=("$final_bl")
    fi
    merge_args+="$offset $filename "

done <<< "$org_content"

echo "merge_args=$merge_args"

esptool.py --chip "$chip" merge_bin -o "$output_file" $merge_args