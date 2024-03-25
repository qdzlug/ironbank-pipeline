# pipeline1

pipeline1 is a major change to ironbank-pipeline structure, including:

- multi-architecture support __\*BETA*__
- single container image for all CI jobs
- flattened directory structure
- streamlined stages

## multi-architecture support __\*BETA*__

Pipeline1 may build amd64, arm64, or both:

- Enable w/ `ENABLE_MULTIARCH` CICD var (any non-blank value)
  - If `Dockerfile` is present, an amd64 image is built
  - If `Dockerfile.arm64` is present, an arm64 image is built
  - If both files are present, both images are built
- A manifest list (list of container images) containing the images is published to registry1
  - If `ENABLE_MULTIARCH` is unset, an amd64 image may replace the manifest list in registry1
- Cosign signatures and SBOM attestations continue to be provided per image; and now also provided to the manifest list
- While in beta status, VAT and ironbank.dso.mil will reference arm64 images by tag with the `-arm64` suffix

## single container image for all CI jobs

[`registry1.dso.mil/ironbank-apps/ironbank-pipelines/pipeline-runner:0.12.0+`](https://repo1.dso.mil/dsop/ironbank-pipelines/pipeline-runner)

To support a single container for all CI jobs, the following software has been added:

- anchorectl
- podman (w/ debian.tar and suse.tar)
- trufflehog3
- twistcli

## flattened directory structure

The directory is now a single level and each directory represents a stage. This helps debug and develop the pipeline, note:

- each stage is a directory and stages are based on `dependencies`
- the directories are numbered to present in execution order
- job scripts in a stage are found in the associated stage directory
- example:
  - now: `7-publish/check-findings`; `7-publish/generate-documentation`; `7-publish/harbor`
  - previous: `post-vat/check-findings`; `generate-documentation/generate-documentation`; `publish-artifacts/harbor`

## streamlined stages

### no 'downstream pipeline' (a.k.a. gitlab `trigger:`)

A [gitlab trigger (downstream pipeline)](https://docs.gitlab.com/ee/ci/pipelines/downstream_pipelines.html) was previously used to influence the image during OpenSCAP's scan. The `image:` is determined during pipeline execution (`image_inspect.py` examining the base container). The `image:` is not known before the pipeline runs, and:

- Gitlab cannot modify a pipeline during execution (CI job A cannot set the image used in CI job B)
- Gitlab can modify a 'downstream pipeline' (CI job A passes `OPENSCAP_IMAGE: debian` to `trigger:` => `trigger:` defines a CI job with `image: ${OPENSCAP_IMAGE}`)

Removing the downstream pipeline decreases complexity, removes redundant CI jobs (because artifact sharing is not implemented), and unburdens users (the UI requires less effort to view an entire pipeline). The removal was achieved by adding the debian and suse openscap scanner images to the pipeline-runner image. The debian or suse scanner is run (via podman) when needed in a pipeline. Redhat images are scanned natively by pipeline-runner (pipeline-runner is redhat based).

### note about reducing CI jobs

CI jobs are expensive (time spent waiting). There are significant initialization and termination periods that cause a delay between one job and the next, examples:

- 30-60 seconds: a new autoscaling node is created because not enough nodes exist to satisfy CI job demand, and that node must pull required container images
- 5-10 seconds: a ci job terminates but must archive and upload CI artifacts to S3
- 5-10 seconds: a ci job initializes but must download and unarchive CI artifacts from S3
- 5-10 seconds: gitlab (internally) polls a pipeline, sees all dependencies succeeded, then schedules the next job in the pipeline

To reduce time spent waiting:

- Ensure a minimum number of nodes are available for business-hours activity
- Use a single CI job whenever possible, e.g. one job to setup ironbank-modules AND run trufflehog AND validate hardening_manifest.yaml (instead of three separate ci jobs)

### naming/image/jobs outline

Each stage now versus previous. If a unique image was previously used, its shown in parenthesis. The major change is `0-setup`.

0. setup

- now:
  - setup/setup
- previous:
  - trigger.yaml:
    - .pre/load-scripts
    - validate-container-metadata/lint-and-image-inspect
    - validate-container-metadata/trufflehog (trufflehog3)
  - globals.yaml
    - .pre/load-scripts
    - validate-container-repository/lint
    - validate-container-repository/trufflehog (trufflehog3)

1. pre-build

- now:
  - prebuild/import-artifacts
- previous:
  - import-artifacts/import-artifacts

2. build

- now:
  - build/build-amd64
  - build/build-arm64
- previous:
  - build/build

3. post-build

- now:
  - post-build/create-sbom
  - post-build/create-tar
- previous:
  - post-build/create-sbom (anchore enterprise)
  - post-build/create-tar

4. pre-scan

- now:
  - pre-scan/scan-logic
- previous:
  - scan-logic/scan-logic

5. scan

- now:
  - scan/anchore-scan
  - scan/twistlock-scan
  - scan/openscap-compliance
- previous:
  - scanning/anchore-scan (anchore enterprise)
  - scanning/twistlock-scan (twistcli)
  - scanning/openscap-compliance (ib-oscap-redhat / ib-oscap-debian / ib-oscap-suse)

6. pre-publish

- now:
  - pre-publish/vat
- previous:
  - vat/vat

7. publish

- now:
  - publish/check-cves
  - publish/check-findings
  - publish/generate-documentation
  - publish/harbor
  - publish/update-staging-attestations
- previous:
  - post-vat/check-cves
  - post-vat/check-findings
  - generate-documentation/generate-documentation
  - publish-artifacts/harbor
  - publish-artifacts/update-staging-attestations

8. post-publish

- now:
  - post-publish/upload-to-s3
  - post-publish/manifest
- previous:
  - publish-artifacts/upload-to-s3
