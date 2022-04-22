# Github action to build and test ESP firmware

This Github action allows you to build and test ESP firmware images.

## Repo requirements
In the repo using this actions you must have
* `gitpod.yml` - The action extracts the build container out of it
* `fw-package.env`- The action extracts the project name out of it
* `make-firmware-pkg.sh` - The action calls this script to generate the firmware package

## Logic

This action can be used in push-tag and pull-request workflows. 

### Behaviour in PR request workflows
```
build firmware package
  V
push firmware package to minio
  V
Test firmware package from minio on test station
```

### Behaviour in push-tag workflows
```
build firmware package
  V
push firmware package to minio
  V
Test firmware package from minio on test station
  V
Generate release
```


## Usage

```yaml
name: fw-image
on:
  push:
    # Sequence of patterns matched against refs/tags
    tags:
      - "[0-9]+.[0-9]+.[0-9]+*"
  pull_request:
    branches:
      - main

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build and Test
        uses: ci4rail/fw_esp-action@initial
        with:
          pipeline-name: "${{ github.repository }}"
          device-name: "iou01_1"
          # This name is resolved by tailscale magic DNS
          teststation-broker-url: "lizard-rpi:1883"
          test-name: "iou01 all"
          access-token: ${{ secrets.FW_CI_TOKEN }}
          # must be a reusable, emphemeral key!
          tailscale-key: ${{ secrets.YODA_TAILSCALE_AUTHKEY }}
          minio-access-key: ${{ secrets.MINIO_ACCESS_KEY }}
          minio-secret-key: ${{ secrets.MINIO_SECRET_KEY }}
```