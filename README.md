# Github workflows to build and test ESP firmware

Repo with workflows build and test ESP firmware images:
* `standard.yml`: Standard ESP firmware images (without Secure Boot)
* `secure_bootloader.yml`: Signed Bootloaders for Secure Boot
* `secure_app.yml`: Secure firmware images (referencing a signed bootloader)

Beside the firmware package, the workflows also create a license archive containing
* SPDX SBOM (Software Bill of Materials) in SPDX format
* All 3rd party licenses
* Notices File

## Repo requirements
In the repo using this actions you must have

* `devcontainer/devcontainer.json` - The action extracts the build container out of it. The image must be one of `ci4rail/esp-idf*` with esp-idf version >= 5.4.
  
* `fw-package.env`- The action extracts the project name out of it. Not required for secure bootloader builds.

To create correct SBOM, you should have sbom.yml manifests in the top level and in each component folder.

### Repo Environments

For secure workflows, you must have the following environments configured in your repo:

* production
* staging

In both environments, you must have the following vars (not secrets) configured:
  * `FIRMWARE_SIGNING_AZURE_APP_ID`
  * `FIRMWARE_SIGNING_AZURE_KEY_ID` - for secure app builds
  * `FIRMWARE_SIGNING_AZURE_KEY_IDS` - for secure bootloader builds


## External services required

* Self-hosted github runner with dind, tags [self-hosted, linux, x64]
* Ci4Rail Teststation with MQTT broker reachable via Tailscale (if tests are not skipped)
* Minio server reachable for pushing firmware packages to teststation
* Azure key vault(s) for secure bootloader and app signing

## Logic

This action can be used in push-tag and pull-request workflows. 

### Behavior in PR request workflows
```
build firmware
  V
sign firmware package for production and staging (if secure)
  V
create firmware package
  V
push firmware package to minio
  V
Test firmware package from minio on test station
```

### Behavior in push-tag workflows

same as above, plus
```
  V
create github release in current repo
  V
create github release in public repo (if configured)
```


## Usage

### Secure Bootloader example

```yaml
name: CI
on:
  push:
    tags:
      - "[0-9]+.[0-9]+.[0-9]+*"
  pull_request:
    branches:
      - main

jobs:
  ci:
    uses: ci4rail/fw_esp-action/.github/workflows/secure_bootloader.yml@v10
    with:
      firmware_signing_azure_subscription_id: ${{ vars.FIRMWARE_SIGNING_AZURE_SUBSCRIPTION_ID }}
      firmware_signing_azure_tenant_id: ${{ vars.FIRMWARE_SIGNING_AZURE_TENANT_ID }}
```

### Secure App example

```yaml
name: CI
on:
  push:
    tags:
      - "[0-9]+.[0-9]+.[0-9]+*"
  pull_request:
    branches:
      - main

jobs:
  ci:
    uses: ci4rail/fw_esp-action/.github/workflows/secure_app.yml@v10
    with:
      firmware_signing_azure_subscription_id: ${{ vars.FIRMWARE_SIGNING_AZURE_SUBSCRIPTION_ID }}
      firmware_signing_azure_tenant_id: ${{ vars.FIRMWARE_SIGNING_AZURE_TENANT_ID }}
      teststation-broker: lizard-rpi:1883
      test-name: "sio06-all"
      test-device-name: "sio06-1"
      target-commitish: "main"
      bootloader-repo: "ci4rail/fw_esp_sio06_01_bootloader"
      bootloader-release-tag: "1.0.0"
      license-contact: "info@ci4rail.com"
      company: "Ci4rail GmbH"
      public-release-repo: "ci4rail/fw_sio06_01_default_releases"
    secrets:
      access-token: ${{ secrets.FW_CI_TOKEN }}
      tailscale-key: ${{ secrets.YODA_TAILSCALE_AUTHKEY }}
      minio-access-key: ${{ secrets.MINIO_ACCESS_KEY }}
      minio-secret-key: ${{ secrets.MINIO_SECRET_KEY }}
```

### Standard App example

```yaml
name: CI
on:
  push:
    # Sequence of patterns matched against refs/tags
    tags:
      - '[0-9]+\.[0-9]+\.[0-9]+*'
  pull_request:
    branches:
      - main

jobs:
  ci:
    uses: ci4rail/fw_esp-action/.github/workflows/standard.yml@v10
    with:
      teststation-broker: lizard-rpi:1883
      test-name: ""
      test-device-name: "dummy-device"
      target-commitish: ""
      license-contact: "info@ci4rail.com"
      company: "Ci4rail GmbH"
      public-release-repo: ""
      generate-licensing-info: false
    secrets:
      access-token: ${{ secrets.FW_CI_TOKEN }}
      tailscale-key: ${{ secrets.YODA_TAILSCALE_AUTHKEY }}
      minio-access-key: ${{ secrets.MINIO_ACCESS_KEY }}
      minio-secret-key: ${{ secrets.MINIO_SECRET_KEY }}
