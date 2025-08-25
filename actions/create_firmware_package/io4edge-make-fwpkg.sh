#!/bin/bash

set -o errexit   # abort on nonzero exitstatus
set -o pipefail  # don't hide errors within pipes

if [ -z ${6} ]; then
  echo "Usage: ${0} <fw-binary> <full-hw-name> <fw-variant> <fw-version> <major-revs> <output-file-suffix>"
  exit 1
fi

if ! [ -x "$(which jq)" ]; then
  echo 'Error: jq is not installed.' >&2
  exit 1
fi

fw_binary=${1}
full_hwname=${2}
fw_variant=${3}
fw_version=${4}
major_revs="[${5}]"
output_file=${6}

# strip away everything before first '-'
short_hwname=$(echo ${full_hwname} | cut -d - -f 2)

fw_binary_basename=$(basename ${fw_binary})

# create dir to tar to
tmp_dir=$(mktemp -d -t make-fwpkg-XXXXXXXXXX)

function finish {
  rm -rf ${tmp_dir}
}
trap finish EXIT

cp -a ${fw_binary} ${tmp_dir}/

jq ".name = \"${short_hwname}-${fw_variant}\" | .version = \"${fw_version}\" | .file = \"${fw_binary_basename}\" | .compatibility.hw = \"${full_hwname}\" | .compatibility.major_revs = ${major_revs}" \
>${tmp_dir}/manifest.json \
<<EOF
{
    "name": "x",
    "version": "y",
    "file": "y",
    "compatibility": {
        "hw": "z",
        "major_revs": [1, 2]
    }
}
EOF

cat ${tmp_dir}/manifest.json

pkg_name=fw-${short_hwname}-${fw_variant}-${fw_version}${output_file_suffix}.fwpkg

tar cf ${pkg_name} -C ${tmp_dir} . --owner=root --group=root

echo created ${pkg_name}
echo "fwpkg=${pkg_name}" >> $GITHUB_OUTPUT