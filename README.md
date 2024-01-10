# ironbank-pipeline

## Getting started

If this is your first time contributing to this repo, please read our contributing.md guide. This guide provides steps for setting up your local environment as well as information regarding best practices when contributing to this code base.

## ironbank-pipeline directory structure

`/templates` contains the templates for the pipeline.
This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the stages required to run.
This directory will also contain templates for special cases, such as distroless or scratch images.
These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.

`/stages` contains the stages which are involved in pipeline execution.
Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file.
The `base.yaml` file dictates the actions and requirements needed for the stage to execute.
Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Contributor project requirements for ironbank-pipeline use

### Adding a project pipeline in settings

The Iron Bank pipelines team will control the project configuration.
As a result, projects _must not_ contain a `.gitlab-ci.yml`.
The Iron Bank Pipelines team has set up project templates which are used in the creation of the repo.
The template provides a CI configuration path which enables the pipeline for the project.

The following steps outline how the custom CI configuration path is set:

`Settings` > `CI / CD` > `General pipelines` > `Custom CI configuration path`

The following is provided: `templates/default.yaml@ironbank-tools/ironbank-pipeline`

This will point the project towards the default pipeline in ironbank-pipeline.

The `default` template will allow images based on UBI to run through the required pipeline steps (whether the image directly uses an UBI base image for its base image, or by using an approved Iron Bank container with a base UBI image for its base image).
The other approved template is `templates/distroless.yaml@ironbank-tools/ironbank-pipeline`, and is used for distroless and scratch based images.

Please review templates/README.md for more information on which template your project needs.

## Pipeline artifacts

To access artifacts for each job, select the job in the UI on the `CI/CD -> Pipelines` page by clicking on the button for that job.
In the top right hand corner of the screen, there is a box which says "Job artifacts" and contains buttons which say "Keep", "Download", and "Browse". Select the button which corresponds to the option you want.

Job artifacts are retained for the latest pipeline, removed after one week in most cases.
A new pipeline run will need to occur in order to produce job artifacts after this period of time.

## Pipeline stages

### .pre (preprocess)

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

### validate-container-repository

The `validate-container-repository` stage contains two jobs, `lint` and `trufflehog`.
`lint` runs a number of python scripts to validate a project's structure, and individual file structure.
`trufflehog` is a python tool to look for secrets or passwords contained in commits pushed to Repo1 (GitLab).

#### lint

The `lint` scripts run, include:

##### folder-structure

The `folder_structure` function will check for the required files, and validate some of these as well, excluding the hardening manifest as a separate functions will check this.

- validate_files_exist
- validate_clamav_whitelist_config
- validate_trufflehog_config
- validate_dockerfile
- pipeline_auth_status

##### hardening manifest validation

The `hardening_manifest_validation` function will run jsonschema validation, as well as create an environment file with variables used later in the pipeline.

Job artifacts:

- project variables which are used in later pipeline stages.

##### docker file validation

Checks to make sure a proper `FROM` command is used for a project's base image

##### base image validation

If a base image is used, checks to make sure it exists in [Registry1](https://registry1.dso.mil/ironbank).
`skopeo` is used to perform the base image inspect.

Job artifacts:

- base_image.json which contains the base image digest

#### trufflehog

Scans for secrets and keys in commits pushed to the remote.
If there is a finding, a command is logged to demonstrate how to run the scan locally, in order to see the finding(s).

### import artifacts

The `import artifacts` stage will download the external resources and validate that the checksums calculated upon download match the checksums provided in the `hardening_manifest.yaml` file.

Assuming this stage validates that the external resources are indeed the ones intended to be used within the container build, it passes along the external resources as artifacts in order to be used in the later `scan-artifacts` and `build` stages.

Job artifacts:

- (if provided) - external resources provided in `hardening_manifest.yaml` such as binaries, tarballs, RPMs, etc.
- (if provided) - images - a tar format of images pulled from public registries, as provided in `hardening_manifest.yaml`.

For more information on this stage, please refer to the [import-artifacts readme](https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/blob/master/stages/artifacts-secrets/README.md).

### build

The `build` stage builds the hardened container image.
The build stage has access to any resources obtained in the `import artifacts` stage and access to the `Dockerfile` included in the container project repository.
An egress policy has been set up to ensure that there are no external calls to the internet from this stage.
The `build` stage utilizes the base image arguments provided in the project `Dockerfile` in order to build the project.
It will pull approved versions of images from Harbor for use as the base image in the container build.

The `build` stage will push the built image to the Registry1 staging registry.

Job artifacts:

- image id as IMAGE_ID, image digest as IMAGE_PODMAN_SHA, staging image name (`<staging registry URL>/<image name>:<CI_PIPELINE_ID>`) as IMAGE_FULLTAG, image name as IMAGE_NAME

For more information on this stage, please refer to the [build job readme](https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/blob/master/stages/build/README.md).

### post build

#### create-tar

Uses `skopeo` to create a `docker-archive` tarball of the built image.
This tarball can be tested locally by running `docker load -i <path-to-tar>`.

Job artifacts:

- image tar, output as a `docker-archive`

#### create-sbom

With the use of `syft`, the pipeline generates four separate software bill of materials (SBOM).
The formats are:

| SBOM format    | File type |
| -------------- | --------- |
| cyclonedx      | json      |
| spdx-tag-value | txt       |
| spdx-json      | json      |
| json           | json      |

### scan-logic

The intent of this script is to compare old vs new images and determine which should be scanned.

Sequence:

1. Write new image details (name, tag, commit, digest, build date) to env file
1. Parse New Image Packages
   - Using the access_log and SBOM artifacts from previous pipeline stages, parse each file, log, and save the list of packages for use later
1. Verify Old Image
   - Check if manifest exists (this is not a new tag)
     - From the old image manifest:
       - Check if git commit SHA is the same as old image
       - Check if parent digest is the same as old image
       - Check if old image has a verified signature
   - Go to next step if the manifest exists, commit SHAs are the same, parent digests are the same, and the old image has a verified signature
   - Otherwise, if there is a difference, log that we must scan new image and exit
1. Parse Old Image Packages
   - Using the access_log and SBOM artifacts from the old image's Cosign attestation, parse, log, and save the list of packages for use later
1. Compare the package lists for old and new image
   - If package list match
     - Log that we can scan old image
     - Update env file with old image details (name, tag, commit, digest, build date)
   - If not, log that we can scan new image and exit

### scanning

The `scanning` stage is comprised of multiple image scanning jobs which run in parallel. The scanning jobs are described below.

#### anchore scan

The Anchore scan will generate CVE and compliance-related findings.
This job also utilizes Anchore's ClamAV integration, to run a malware scan on the image.

Job artifacts:

- `anchore-version.txt` - contains the Anchore version which is being used for this job.
- `anchore_api_gates_full.json` - contains DoD checks Anchore looks for in scans.
- `anchore_gates.json` - contains output of compliance checks and findings produced in Anchore scan.
- `anchore_security.json` - contains output of CVE findings produced in Anchore scan.

#### openscap compliance

The OpenSCAP compliance scan will check for any compliance-related findings.

Job artifacts:

- `oscap-version.txt` - displays the version of OpenSCAP used.
- `report.html` - OSCAP Evaluation Report, which contains a list of the rules and any findings.

#### twistlock scan

The Twistlock scan will check for CVE findings in the image.

Job artifacts:

- `{img_version}.json` - results of the Twistlock scan.
- `twistlock-version.txt` - contains the version of Twistlock used to generate the Twistlock scan results.

- {img_version}.json

### vat

This stage will not run on project master or feature branches.

The `vat` stage uses previous pipeline artifacts (notably, from the `scanning` stages) in order to populate the [Vulnerability Assessment Tracker](https://vat.dso.mil) (VAT).
VAT contains the list of the findings associated with the built image in the pipeline, where those with access can justify findings and provide approvals.
For those who are attempting to get their containers approved, they will need to provide their justifications for any findings that cannot be remediated, in the VAT.

### post-vat

#### check cves

The `check cves` stage is configured to notify users of new unjustified or unreviewed findings.
This job uses the `vat_response.json` file from the `vat` stage, to display any findings that the user should be aware of.

The following stages will only run on master branches.

#### check-findings

### generate-documentation

#### generate-documentation

The `generate-documentation` job creates a JSON file with image digest and ID shasums for the ib-manifest. This job also creates JSON files with scan metadata info which includes scan tool versions and commit shashums. Additionally this job generates csv files for the various scans and the `<image-and-pipeline-id>-justifications.xlsx` file.

Job artifacts:

- `scan_metadata.json` - provides metadata from the scans.
- `all_scans.xlsx` - compilation of all scan results in Microsoft Excel format.
- `anchore_gates.csv` - Anchore gates in CSV results.
- `anchore_security.csv` - Anchore security results in CSV format.
- `oscap.csv` - OpenSCAP results in CSV format.
- `<image-and-pipeline-id>-justifications.xlsx` - see description in previous paragraph.
- `summary.csv` - compilation of all scan results in CSV format.
- `tl.csv` - Twistlock results in CSV format.

### publish-artifacts

This stage contains two jobs, `harbor` and `upload-to-s3`.

#### Harbor

Pushes built images to `registry1.dsop.io/ironbank`, as well as performing Cosign operations.
The SBOM files, VAT response file, and Cosign signatures on the image and SBOM artifact, are all pushed to the registry in this stage.

#### Upload to S3

Upload artifacts which are displayed/utilized by the [Iron Bank website](https://ironbank.dso.mil).
The artifacts uploaded include scan reports, project README, project LICENSE, and others.

## CI Vars Consumed Externally

- `PIP_QUIET` is used to supress the output from pip commands

- `SYFT_REGISTRY_AUTH_PASSWORD` and `SYFT_REGISTRY_AUTH_USERNAME` are used for credentials for specific registries: [Link](https://github.com/anchore/syft/blob/main/README.md)

- `TWISTLOCK_USER` and `TWISTLOCK_PASSWORD` are used for TWISTLOCK authentication

## Stargate (Legacy Code)

- Stage and module removed on 03/06/2023
- Last commit SHA: `f5a439a9237ce9ec05b8a6f4ce7e91c96c44f1d5`

## Local Development

Using vscode? Try the [devcontainer](.devcontainer/) to bootstrap a containerized dev environment.

- tested with docker desktop and colima
- for colima, try:

```shell
colima start --cpu 4 --memory 8 --disk 128 --vm-type vz --mount-type virtiofs
# or
colima start --cpu 4 --memory 8 --disk 128 --cpu-type Haswell-v4 --mount-type virtiofs
```

To install tooling locally:

- Linting, formatting, and secret checking of this repo can be done via `make` commands locally.
- Run `make install_dependencies` to install depdencies on your Mac, this will install brew packages and install python depdencies via brew
- Run `poetry shell` to activate the python virtual environment
- `make lint_all` - will run all linters we use against your code
- `make format_check_all` - will run formatting checks without making changes
- `make format_in_place` - will make formatting fixes to your code
- `make run_unit_tests` - will run the unittests
- `make check_secrets` - will run trufflehog in a container and will check your commit history for secreets since you branched from master.
