# ironbank-pipeline

## ironbank-pipeline directory structure:

`/templates` contains the templates for the pipeline. This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the jobs required to run. This directory will also contain templates for special cases, such as distroless or scratch images. These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.

`/stages` contains the stages which are involved in pipeline execution. Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file. The `base.yaml` file dictates the actions and requirements needed for the stage to execute. Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Contributor project requirements for ironbank-pipeline use:

- Contributor projects will need to point to the `ironbank-pipeline` project from the `.gitlab-ci.yml` file in their respective projects order to utilize the Container Hardening CI/CD pipeline.

For most projects, add the following block to the `.gitlab-ci.yml` file in the project in order to do this:

```
include:
  - project: 'ironbank-tools/ironbank-pipeline'
    file: '/templates/default.yaml'
```

The `default` template will allow images based on UBI to run through the required pipeline steps (whether the image directly uses an UBI base image for its base image, or by using an approved IronBank container with a base UBI image for its base image).

Containers which utilize the distroless base image should instead use the following block in the project's `.gitlab-ci.yml` file:

```
include:
  - project: 'ironbank-tools/ironbank-pipeline'
    file: '/templates/distroless.yaml'
```

This will omit the OpenSCAP scan jobs from the pipeline. OSCAP scanning is not compatible with containers built on distroless base images.

- Contributors will also need to provide the current image version of the container which is being built in the project's `.gitlab-ci.yml` file using the `IMG_VERSION` variable.

For example, if the current container version is 2.0.1, the contributor would add the following to the project's `.gitlab-ci.yml` file:

```
variables:
  IMG_VERSION: "2.0.1"
```

## Pipeline stages

#### preprocess

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

#### preflight

The `preflight` stage performs two functions, which are described below:

- displaying the folder structure for the project which is running through the Container Hardening pipeline. The `folder structure` job will check for the existence of the following files and/or directories within the project which is being run through the pipeline:

  - README (required file)
  - Dockerfile (required file)
  - LICENSE (required file)
  - download.yaml (file, not always required, which allows external resources to be validated and used in the container build)
  - scripts (directory, not always required, which stores any script files needed in the container)
  - signatures (directory, not always required, which contains signatures needed for validation of any repository or external resource files)
  - config (directory, not always required, which stores any configuration files needed in the container)
  - accreditation (directory, not always required, which provides information about approved images)

- testing/checking the build variables exist using the `build variables` job.

The preflight stage is currently set to allow failures because the `folder structure` job is listing some optional files/directories

#### lint

The `lint` stage contains multiple jobs and is used to ensure the formatting used in various project files is valid.

The `yaml lint` and `dockerfile lint` jobs are used to ensure the proper formatting of the following files in each project: `.gitlab-ci.yml`, `download.yaml`/`download.json` file, and `Dockerfile`.

The `wl compare lint` job ensures that the pipeline run will fail on any branch if the repository structure is incorrect, or if the greylist files can't be retrieved or have a mismatched image name/tag.

#### import artifacts

The `import artifacts` stage will import any external resources (resources from the internet) provided in the `download.yaml` file for use during the container build. The `import artifacts` stage will download the external resources and validate that the checksums calculated upon download match the checksums provided in the `download.yaml` file.

Assuming this stage validates that the external resources are indeed the ones intended to be used within the container build, it passes along the external resources as artifacts in order to be used in the later `scan-artifacts` and `build` stages.

#### scan artifacts

The `scan artifacts` stage performs an anti-virus/malware scan on the resources obtained in the `import artifacts` stage (if the project includes a `download.yaml` file). This will help guard against any malicious software/code being used in the container build. This stage utilizes ClamAV scans to perform the anti-virus/malware scanning. The scans database is updated each pipeline run, using the `freshclam` command, so that the list of vulnerabilities in the scanning database is always up to date.

The `scan artifacts` stage will automatically fail if there are infected files found in the resources downloaded in the `import artifacts stage`. `scan artifacts` produces a text file which contains the results of the ClamAV scan.

#### build

The `build` stage builds the hardened container image. The build stage has access to any resources obtained in the `import artifacts` stage and access to the `Dockerfile` included in the container project repository. An egress policy has been set up to ensure that there are no external calls to the internet from this stage. The `build` stage utilizes the base image arguments provided in the project `Dockerfile` in order to build the project. It will pull approved versions of images from Harbor for use as the base image in the container build.

#### scanning

The `scanning` stage is comprised of multiple image scanning jobs which run in parallel. The scanning jobs are described below.

##### anchore scan

The Anchore scan will generate CVE and compliance-related findings.

Job artifacts:

- `anchore-version.txt` - contains the Anchore version which is being used for this job
- `anchore_api_gates_full.json`
- `anchore_gates.json`
- `anchore_security.json`

##### openscap compliance

The OpenSCAP compliance scan will check for any compliance-related findings.

Job artifacts:

- `oscap-version.txt`
- `report.html`
- `cve-oval.xml`

##### openscap cve

The OpenSCAP CVE scan will check for CVE findings in the image.

Job artifacts:

- `report-cve.html`
- `report-cve.xml`

##### twistlock scan

The Twistlock scan will check for CVE findings in the image.

Job artifacts:

- {img_version}.json

#### csv-output

The `csv-output` stage will generate CSV files for the various scans and the `all-scans.xlsx` file. These documents can be found in the artifacts for this stage.

The generated documents serve two purposes at the moment:

- the creation of `all-scans.xlsx` so that Containher Hardening team members can access the list of findings for the container they are working on. This file can be accessed by vendors as well. The `all-scans.xlsx` file is a compilation of the findings generated from the Twistlock, Anchore, and OpenSCAP scans in the `scanning` stage and is used as the location for submitting justifications.
- the CSV files from each of the scans are used by the VAT.

#### check cves

The `check cves` stage is configured to prevent the publishing of images which do not have whitelisted vulnerabilities. This stage checks the `dccscr-whitelists` repository to retrieve the whitelist for the image and will verify that the scan results generated from the `csv-output` stage do not contain any findings which have not been justified/whitelisted. This prevents the image from being published to the IronBank website or the Harbor registry with security vulnerabilities we are not aware of or have been justified and approved.

In time, this stage will utilize the VAT tool to compare the whitelisted vulnerabilities instead of the whitelists.

#### documentation

The `documentation` stage consists of multiple jobs.

- `create mapping website` - this job provides a `repo_map.json` file which contains comprehensive information about the container as well as the location of various files within our storage mechanism. This allows the IronBank website to retrieve the information for display on the IronBank website.
- `sign image` - this job will do a gpg signing of the image so that end users can validate that the image is from the IronBank and the one they intend to download.

### Adding a project pipeline in settings

Go to the settings for a specific project

`Settings` > `CI / CD` > `General pipelines` > `Custom CI configuration path`
Enter the following: `templates/default.yaml@ironbank-tools/ironbank-pipeline`

This will point the project towards the default pipeline in ironbank-pipeline.
