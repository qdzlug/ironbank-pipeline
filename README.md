# ironbank-pipeline

## ironbank-pipeline directory structure

`/templates` contains the templates for the pipeline.
This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the jobs required to run.
This directory will also contain templates for special cases, such as distroless or scratch images.
These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.

`/stages` contains the stages which are involved in pipeline execution.
Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file.
The `base.yaml` file dictates the actions and requirements needed for the stage to execute.
Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Contributor project requirements for ironbank-pipeline use

- ### Adding a project pipeline in settings

The Iron Bank pipelines team will control the project configuration.
As a result, projects _must not_ contain a `.gitlab-ci.yml`.
The Iron Bank Pipelines team has set up project templates which are used in the creation of the repo.
The template provides a CI configuration path which enables the pipeline for the project.

The following steps outline how the custom CI configuration path is set:

`Settings` > `CI / CD` > `General pipelines` > `Custom CI configuration path`

The following is provided: `templates/default.yaml@ironbank-tools/ironbank-pipeline`

This will point the project towards the default pipeline in ironbank-pipeline.

The `default` template will allow images based on UBI to run through the required pipeline steps (whether the image directly uses an UBI base image for its base image, or by using an approved Iron Bank container with a base UBI image for its base image).

Please review templates/README.md for more information on which template your project needs.

## Pipeline artifacts

To access artifacts for each job, select the job in the UI on the `CI/CD -> Pipelines` page by clicking on the button for that job.
In the top right hand corner of the screen, there is a box which says "Job artifacts" and contains buttons which say "Keep", "Download", and "Browse". Select the button which corresponds to the option you want.

Job artifacts are removed after one week in most cases.
A new pipeline run will need to occur in order to produce job artifacts after this period of time.

## Pipeline stages

### preprocess

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

Job artifacts:

- pipeline templates/scripts/etc.

### preflight

The `preflight` stage performs multiple functions, which are described below:

- displaying the folder structure for the project which is running through the Container Hardening pipeline.

- testing/checking the build variables exist using the `build variables` job.

- The `metadata.py` file processes the `hardening_manifest.yaml` file
  - The structure of the file is validated using the `hardening_manifest.schema.json` jsonschema.
  - The image name, version (first tag), tags, build args, and labels are extracted for use in later build steps

### lint

The `lint` stage contains multiple functions and is used to ensure the formatting used in various project files is valid.

The `wl compare lint` job ensures that the pipeline run will fail on any branch if the repository structure is incorrect.

The `folder structure` job will check for the existence of the following files and/or directories within the project which is being run through the pipeline:

    - README.md (required file)
    - Dockerfile (required file)
    - LICENSE (required file)
    - hardening_manifest.yaml (required, includes container metadata and allows external resources to be validated and used in the container build)
    - scripts (directory, not always required, which stores any script files needed in the container)
    - signatures (directory, not always required, which contains signatures needed for validation of any repository or external resource files)
    - config (directory, not always required, which stores any configuration files needed in the container)
    - accreditation (directory, not always required, which provides information about approved images)

Job artifacts:

- project variables which are used in later pipeline stages.

### import artifacts

The `import artifacts` stage will import any external resources (resources from the internet) provided in the `hardening_manifest.yaml` file for use during the container build.
The `import artifacts` stage will download the external resources and validate that the checksums calculated upon download match the checksums provided in the `hardening_manifest.yaml` file.

Assuming this stage validates that the external resources are indeed the ones intended to be used within the container build, it passes along the external resources as artifacts in order to be used in the later `scan-artifacts` and `build` stages.

Job artifacts:

- (if provided) - external resources provided in `hardening_manifest.yaml` such as binaries, tarballs, RPMs, etc.
- (if provided) - images - a tar format of images pulled from public registries, as provided in `hardening_manifest.yaml`.

For more information on this stage, please refer to the [import-artifacts readme](https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/blob/master/stages/import-artifacts/README.md).

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

### scanning

The `scanning` stage is comprised of multiple image scanning jobs which run in parallel. The scanning jobs are described below.

#### anchore scan

The Anchore scan will generate CVE and compliance-related findings.

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

### csv-output

The `csv-output` stage will generate CSV files for the various scans and the `<image-and-pipeline-id>-justifications.xlsx` file.
These documents can be found in the artifacts for this stage.

Job artifacts:

- `all_scans.xlsx` - compilation of all scan results in Microsoft Excel format.
- `anchore_gates.csv` - Anchore gates in CSV results.
- `anchore_security.csv` - Anchore security results in CSV format.
- `oscap.csv` - OpenSCAP results in CSV format.
- `<image-and-pipeline-id>-justifications.xlsx` - see description in previous paragraph.
- `summary.csv` - compilation of all scan results in CSV format.
- `tl.csv` - Twistlock results in CSV format.

### check cves

The `check cves` stage is configured to prevent the publishing of images which do not have whitelisted vulnerabilities.
This stage checks the `dccscr-whitelists` repository to retrieve the whitelist for the image and will verify that the scan results generated from the `csv-output` stage do not contain any findings which have not been justified/whitelisted.
This prevents the image from being published to the Iron Bank website or the Harbor registry with security vulnerabilities we are not aware of or have been justified and approved.

In time, this stage will utilize the VAT tool to compare the whitelisted vulnerabilities instead of the whitelists.

#### Stage Dependencies

- load-scripts
- anchore-scan
- anchore-scan
- hardening-manifest
- build

#### Required Artifacts

#### Generated Artifacts

Artifacts are placed in the directory: ${ARTIFACT_STORAGE}/allowlists.
The `ARTIFACT_STORAGE` variable is a variable in the pipeline.
The value will not be documented as variables by their nature may change.

#### Required Python Libraries

Refer to [pyproject.toml](https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/blob/master/pyproject.toml) for all required python libraries.

### documentation

This stage will only run on master branches.

The `documentation` stage consists of two jobs.

#### ib-manifest

Creates a JSON file with image digest and ID shasums.

#### write-json-docs

Creates JSON files with scan metadata info. Includes scan tool versions and commit shasum

Job artifacts:

- `scan_metadata.json` - provides metadata from the scans.

### Harbor

Pushes built images to `registry1.dsop.io/ironbank`, as well as performing Cosign operations.
The SBOM files, VAT response file, and Cosign signatures on the image and SBOM artifact, are all pushed to the registry in this stage.

### Upload to S3

Upload artifacts which are displayed/utilized by the [Iron Bank website](https://ironbank.dso.mil).
The artifacts uploaded include scan reports, project README, project LICENSE, and others.
