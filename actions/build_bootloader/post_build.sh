#!/usr/bin/env bash

# Arguments: 
# $1: project-name

if [ -z "$1" ]; then
  echo "Error: too few arguments"
  exit 1
fi

project_name=$1

build_dir=$(find . -maxdepth 1 -type d -name 'build*' -printf '%f\n' | sort | head -n1)
echo ${build_dir}

version=$(awk 'match($0,/PROJECT_VER=\\"[\.a-z0-9\-]+\\"/) { print substr($0,RSTART+14,RLENGTH-16)}' ${build_dir}/build.ninja)
bl_file=${project_name}-${version}.bin
bl_file_path=${build_dir}/bootloader/${bl_file}
cp ${build_dir}/bootloader/bootloader.bin ${bl_file_path}

echo "build-dir=${build_dir}" >> $GITHUB_OUTPUT
echo "bootloader-file=${bl_file}" >> $GITHUB_OUTPUT
echo "bootloader-file-path=${bl_file_path}" >> $GITHUB_OUTPUT
echo "version=${version}" >> $GITHUB_OUTPUT
