# Templates

## This page is for informational purposes only to provide visibility into the Iron Bank pipeline. Contributors should work with the Iron Bank pipelines team in order to have the appropriate template created if needed for their project

This directory contains the pipeline templates for the upstream/downstream components of the container hardening pipeline. The files in the root of this directory contain general configuration used in all pipelines and the templates in the `downstream` directory have specific configuration to ensure stages operate as needed based on the os type of the parent image being built in the pipeline. For base images (ubi, distroless, etc.), the os type is pulled from a label (mil.dso.ironbank.os-type) in the hardening manifest. For images with at least one IB parent (openjdk, gradle-jdk, etc.), the base image in the hardening manifest is used to inspect the image in registry1 and gather the same label. This label will exist for any newly built/published images in registry1, because it will either be provided from the hardening manifest or by the parent image at build time.

The list of templates is as follows:

### base templates

- `trigger.yaml` - The upstream pipeline definition. It's main purpose is to discover the os-type of the image being built and kick off the downstream pipeline with the appropriate template
- `globals.yaml` - The downstream pipeline definition. This is the actual hardening pipeline that handles building, scanning, publishing, etc.
- `setup_modules.yaml` - A single job that will setup the ironbank-modules in a before script. Used with `extends` for any job in the pipeline that uses ironbank-modules
- `shared_vars.yaml` - Variables shared between the upstream and downstream pipelines

### downstream templates

> For all images that skip the oscap stage, this is due to a lack of a specific ssg for their image type and a lack of a generic ssg for us to consume.

- `alpine.yaml`
  - skips oscap stage
- `chainguard.yaml`
  - skips oscap stage
- `debian.yaml`
  - uses custom ubuntu based image for openscap scanning
- `distroless.yaml`
  - skips oscap stage
  - [related ticket](https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/issues/903)
- `suse.yaml`
  - uses custom suse based image for openscap scanning
- `ubi.yaml`
  - uses default oscap-podman image for oscap scanning
- `ubuntu.yaml`
  - uses custom ubuntu based image for openscap scanning

### Stages

#### .pre (preprocess)

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

#### validate-container-metadata

This stage contains two jobs, `lint-and-image-inspect` and `trufflehog`. The main goal of this stage is to check the container metadata, output environmental variables that are used by the downstream pipeline and to run the `trufflehog` python tool.

##### lint-and-image-inspect

- This job calls the `stages/validate-container-repository/lint/validate_hardening_manifest.py` file to make sure the _hardening_manifest_ file is in the correct format.
- The job will then call `stages/os-type/image_inspect.py` to determine the os-type of the image being built, pull the corresponding image if needed, and wite this to an environment variable.

##### trufflehog

- Calls the `/stages/validate-container-repository/secret-scan/trufflehog.py` file to scan for secrets and keys in commits pushed to the remote repo.
- If there is a finding, a command is logged to demonstrate how to run the scan locally, in order to see the finding(s).

#### pipeline trigger

This stage is used to kickoff the downstream pipeline using the _ironbank-tools/ironbank-pipeline_ project and the correct downstream template.
