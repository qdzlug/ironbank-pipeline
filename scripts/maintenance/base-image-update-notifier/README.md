# Platform One Iron Bank Base Image Updater Tool

Accepts a base-image and will search all projects within target-group. If the base-image
is detected, an issue will be created from `./templates/issue.md` telling the maintainer
to update their base image.

## Usage

Use `40` for all of DSOP projects, or more focused `2730` for the python project.

```shell
pip install -r requirements.txt
export VAT_BACKEND_SERVER_ADDRESS="https://vat-protected.dso.mil/api"
python3 notifier.py -u https://repo1.dso.mil -t ${IRONBANK_TOOLS_TOKEN} -g 2680
```

## VAT API Integration

For the swagger UI: https://vat-protected.dso.mil/api/p1/

For the doc: https://vat-protected.dso.mil/api/p1/swagger

You must connect to [Appgate SDP](https://confluence.il2.dso.mil/display/P1/Platform+One+CNAP+AppGate+SDP+Client) to access the VAT api.

## What does it do?

Looks for the following in hardening_manifest.yaml:

```
args:
  BASE_IMAGE: "redhat/ubi/ubi8"
  BASE_TAG: "8.5"
```

And for the following in Dockerfile:

```
ARG BASE_IMAGE=ironbank/redhat/ubi/ubi8
ARG BASE_TAG=8.5
```

Attempts to perform a MR and an issue tracking the MR.
