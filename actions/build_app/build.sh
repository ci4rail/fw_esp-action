#!/usr/bin/env bash

# Arguments: 
# $1: app-build-command
# $2: build-dfu
# $3: project-name

if [ -z "$3" ]; then
  echo "Error: too few arguments"
  exit 1
fi

app_build_command=$1
build_dfu=$2
project_name=$3

rm -rf build*

source /opt/esp/idf/export.sh
git config --global --add safe.directory /opt/esp/idf 
${app_build_command}


if [ "${build_dfu}" = "true" ]; then
    idf.py dfu
fi

build_dir=$(find . -maxdepth 1 -type d -name 'build*' -printf '%f\n' | sort | head -n1)
echo ${build_dir}

version=$(awk 'match($0,/PROJECT_VER=\\"[\.a-z0-9\-]+\\"/) { print substr($0,RSTART+14,RLENGTH-16)}' ${build_dir}/build.ninja)
app_file=${project_name}-${version}.bin
app_file_path=${build_dir}/${app_file}
cp ${build_dir}/${project_name}.bin ${app_file_path}

dfu_file=""
if [ "${build_dfu}" = "true" ]; then
    dfu_file="${app_file_path}.dfu.bin"
    cp ${build_dir}/dfu.bin ${dfu_file}
fi

echo "build-dir=${build_dir}" >> $GITHUB_OUTPUT
echo "app-file=${app_file}" >> $GITHUB_OUTPUT
echo "app-file-path=${app_file_path}" >> $GITHUB_OUTPUT
echo "version=${version}" >> $GITHUB_OUTPUT
echo "dfu-file=${dfu_file}" >> $GITHUB_OUTPUT

echo $GITHUB_OUTPUT