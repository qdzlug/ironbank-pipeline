# pipeline1

pipeline1 is a major change to ironbank-pipeline, these changes come from a handful of places:

* a single image runs all CI jobs
* flattened stage-based directory structure
* removed 'downstream trigger' gitlab construct
* removed some duplicate/redundant setup jobs

## new image / software added

[`registry1.dso.mil/ironbank-apps/ironbank-pipelines/pipeline-runner:0.11.0+`](https://repo1.dso.mil/dsop/ironbank-pipelines/pipeline-runner)

- anchorectl
- podman (w/ debian.tar and suse.tar)
- trufflehog3
- twistcli

## flattened structure

- CI stages are based on dependencies
- CI stages have a single numbered directory
- All job scripts in a stage exist within the CI stage directory
- example:
  - now: `7-publish/check-findings`; `7-publish/generate-documentation`; `7-publish/harbor`
  - previous: `post-vat/check-findings`; `generate-documentation/generate-documentation`; `publish-artifacts/harbor`

## removal of downstream pipeline (`trigger:`)

A [gitlab trigger (downstream pipeline)](https://docs.gitlab.com/ee/ci/pipelines/downstream_pipelines.html) was used because the `image:` for openscap is variable but not known before the pipeline is run..:
- Gitlab does not support modifying a pipeline during execution (CI job A cannot set the image used in CI job B)
- Gitlab does support modifying a downstream pipeline via variables (CI job A sets the image var used in `trigger:` and the trigger pipeline runs CI job B)

The presence of a trigger increases complexity, adds redundant CI jobs (because artifact sharing is not implemented), and burdens users (the UI requires extra effort to view an entire pipeline)

The openscap distro packages are specific to each distro (redhat, debian, or suse). The solution is a pipeline-runner image capable of using all three. This is done by running debian or suse based openscap images inside pipeline-runner (via podman) when needed. Redhat images are scanned natively by pipeline-runner (pipeline-runner is redhat based).

## naming/image/jobs outline

Each stage now versus previous. If a unique image was previously used, its shown in parenthesis.

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
  - build/build
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
- previous:
  - publish-artifacts/upload-to-s3

## note about reducing CI jobs

CI jobs are expensive (time spent waiting, not financially or computationally). There are significant periods during initialization and termination that cause a delay between one job and the next, examples:

* 30-60 seconds: a new autoscaling node is created because not enough nodes exist to satisfy CI job demand, and that node must pull required container images
* 5-10 seconds: a ci job terminates but must archive and upload CI artifacts to S3
* 5-10 seconds: a ci job initializes but must download and unarchive CI artifacts from S3
* 5-10 seconds: gitlab (internally) polls a pipeline, sees all dependencies succeeded, then schedules the next job in the pipeline

There are a few ways to reduce time spent waiting:

- Ensure a minimum number of nodes are available for business-hours activity
- Use a single CI job whenever possible, e.g. one job to setup ironbank-modules, validate hardening_manifest.yaml, and run trufflehog (instead of three separate ci jobs)
