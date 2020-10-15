# ironbank-pipeline


## ironbank-pipeline directory structure:

`/templates` contains the templates for the pipeline. This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the jobs required to run. This directory will also contain templates for special cases, such as distroless or scratch images. These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.


`/stages` contains the stages which are involved in pipeline execution. Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file. The `base.yaml` file dictates the actions and requirements needed for the stage to execute. Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Contributor project requirements for ironbank-pipeline use:

- #### Adding a project pipeline in settings

The Iron Bank pipelines team will control the project configuration. As a result, projects *must not* contain a `.gitlab-ci.yml` The Iron Bank Pipelines team has set up project templates which are used in the creation of the repo. The template provides a CI configuration path which enables the pipeline for the project. In the event this was not created for the project, the following steps outline how it must be changed:

Go to the settings for a specific project

`Settings` > `CI / CD` > `General pipelines` > `Custom CI configuration path`

Enter the following: `templates/default.yaml@ironbank-tools/ironbank-pipeline`

This will point the project towards the default pipeline in ironbank-pipeline.

The `default` template will allow images based on UBI to run through the required pipeline steps (whether the image directly uses an UBI base image for its base image, or by using an approved Iron Bank container with a base UBI image for its base image).

Containers which utilize the distroless base image should instead use the `distroless` template instead of the `default` pipeline template. Please reach out to the Iron Bank Pipelines team or the Container Hardening team for assistance in getting this changed. The `Custom CI configuration path` for distroless-based container projects will be the following:

`templates/distroless.yaml@ironbank-tools/ironbank-pipeline`

This will omit the OpenSCAP scan jobs from the pipeline. OSCAP scanning is not compatible with containers built on distroless base images.

## Pipeline notes

To access artifacts for each job, select the job in the UI on the `CI/CD -> Pipelines` page by clicking on the button for that job. In the top right hand corner of the screen, there is a box which says "Job artifacts" and contains buttons which say "Keep", "Download", and "Browse". Select the button which corresponds to the option you want. 

Job artifacts are removed after one week in most cases. A new pipeline run will need to occur in order to produce job artifacts after this period of time.

## Pipeline stages

#### preprocess

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

Job artifacts:
- pipeline templates/scripts/etc.

#### preflight

The `preflight` stage performs two functions, which are described below:

  - displaying the folder structure for the project which is running through the Container Hardening pipeline. The `folder structure` job will check for the existence of the following files and/or directories within the project which is being run through the pipeline:
      - README (required file)
      - Dockerfile (required file)
      - LICENSE (required file)
      - download.yaml/download.json (file, not always required, which allows external resources to be validated and used in the container build)
      - scripts (directory, not always required, which stores any script files needed in the container)
      - signatures (directory, not always required, which contains signatures needed for validation of any repository or external resource files)
      - config (directory, not always required, which stores any configuration files needed in the container)
      - accreditation (directory, not always required, which provides information about approved images)

  - testing/checking the build variables exist using the `build variables` job.

#### lint

The `lint` stage contains multiple jobs and is used to ensure the formatting used in various project files is valid.

The `yaml lint` and `dockerfile lint` jobs are used to ensure the proper formatting of the following files in each project: `.gitlab-ci.yml`, `download.yaml`/`download.json` file, and `Dockerfile`.

The `wl compare lint` job ensures that the pipeline run will fail on any branch if the repository structure is incorrect, or if the greylist files can't be retrieved or have a mismatched image name/tag.

Job artifacts: 
- project variables which are used in later pipeline stages.

#### import artifacts

The `import artifacts` stage will import any external resources (resources from the internet) provided in the `download.yaml` file for use during the container build. The `import artifacts` stage will download the external resources and validate that the checksums calculated upon download match the checksums provided in the `download.yaml` file.

Assuming this stage validates that the external resources are indeed the ones intended to be used within the container build, it passes along the external resources as artifacts in order to be used in the later `scan-artifacts` and `build` stages.

Job artifacts:
- (if provided) - external resources provided in `download.yaml/download.json` such as binaries, tarballs, RPMs, etc.
- (if provided) - images - a tar format of images pulled from public registries, as provided in `download.yaml/download.json`.

#### scan artifacts

The `scan artifacts` stage performs an anti-virus/malware scan on the resources obtained in the `import artifacts` stage (if the project includes a `download.yaml` file). This will help guard against any malicious software/code being used in the container build. This stage utilizes ClamAV scans to perform the anti-virus/malware scanning. The scans database is updated each pipeline run, using the `freshclam` command, so that the list of vulnerabilities in the scanning database is always up to date.

The `scan artifacts` stage will automatically fail if there are infected files found in the resources downloaded in the `import artifacts stage`.

Job artifacts:
- `import-artifacts-clamav-report.txt` (if external resources/images are used in the build process) - contains the results of the ClamAV scan.

#### build

The `build` stage builds the hardened container image. The build stage has access to any resources obtained in the `import artifacts` stage and access to the `Dockerfile` included in the container project repository. An egress policy has been set up to ensure that there are no external calls to the internet from this stage. The `build` stage utilizes the base image arguments provided in the project `Dockerfile` in order to build the project. It will pull approved versions of images from Harbor for use as the base image in the container build.

The `build` stage will push the built image to the Registry1 staging registry. 

Job artifacts:
- tar file of the image which was built. Contributors can download this artifact and use it on their machine with `docker load -i <image>.tar`.

#### scanning

The `scanning` stage is comprised of multiple image scanning jobs which run in parallel. The scanning jobs are described below.

##### anchore scan

The Anchore scan will generate CVE and compliance-related findings.

Job artifacts:
- `anchore-version.txt` - contains the Anchore version which is being used for this job.
- `anchore_api_gates_full.json` - contains DoD checks Anchore looks for in scans.
- `anchore_gates.json` - contains output of compliance checks and findings produced in Anchore scan.
- `anchore_security.json` - contains output of CVE findings produced in Anchore scan.

##### openscap compliance

The OpenSCAP compliance scan will check for any compliance-related findings.

Job artifacts:
- `oscap-version.txt` - displays the version of OpenSCAP used.
- `report.html` - OSCAP Evaluation Report, which contains a list of the rules and any findings.

##### openscap cve

The OpenSCAP CVE scan will check for CVE findings in the image.

Job artifacts:
- `report-cve.html` - OVAL Results, which contains a list of the results from the OpenSCAP CVE scan.
- `report-cve.xml` - OVAL Results in `.xml` format.

##### twistlock scan

The Twistlock scan will check for CVE findings in the image.

Job artifacts:
- `{img_version}.json` - results of the Twistlock scan.
- `twistlock-version.txt` - contains the version of Twistlock used to generate the Twistlock scan results.


#### csv-output

The `csv-output` stage will generate CSV files for the various scans and the `<image-and-pipeline-id>-justifications.xlsx` file. These documents can be found in the artifacts for this stage.

The generated documents serve two purposes at the moment:
- the creation of `<image-and-pipeline-id>-justifications.xlsx` so that Container Hardening team members and vendors/contributors can access the list of findings for the container they are working on. The `<image-and-pipeline-id>-justifications.xlsx` file is a compilation of the findings generated from the Twistlock, Anchore, and OpenSCAP scans in the `scanning` stage and is used as the location for submitting justifications. This file is a result of running the `justifier.py` script against the `all-scans.xlsx` file in order to produce justifications for findings which have already been approved in parent images or other Iron Bank approved images.
- the CSV files from each of the scans are used by the VAT.

Job artifacts:
- `all_scans.xlsx` - compilation of all scan results in Microsoft Excel format.
- `anchore_gates.csv` - Anchore gates in CSV results.
- `anchore_security.csv` - Anchore security results in CSV format.
- `oscap.csv` - OpenSCAP results in CSV format.
- `oval.csv` - OpenSCAP OVAL results in CSV format.
- `<image-and-pipeline-id>-justifications.xlsx` - see description in previous paragraph.
- `summary.csv` - compilation of all scan results in CSV format.
- `tl.csv` - Twistlock results in CSV format.

#### check cves

The `check cves` stage is configured to prevent the publishing of images which do not have whitelisted vulnerabilities. This stage checks the `dccscr-whitelists` repository to retrieve the whitelist for the image and will verify that the scan results generated from the `csv-output` stage do not contain any findings which have not been justified/whitelisted. This prevents the image from being published to the Iron Bank website or the Harbor registry with security vulnerabilities we are not aware of or have been justified and approved.

In time, this stage will utilize the VAT tool to compare the whitelisted vulnerabilities instead of the whitelists.


#### documentation

This stage will not run on feature branches.

The `documentation` stage consists of multiple jobs.

##### sign image

This job will do a GPG signing of the image with the Iron Bank public key so that end users can validate that the image is from the Iron Bank and the one they intend to download.

Job artifacts:
- `<image-version.sig>` - signature of the image.
- `<image-version.tar>`- tar file of the signed image.

##### sign manifest

This job utilizes the Iron Bank public GPG key in order to sign the container manifest.

Job artifacts:
- `manifest.json` - signed manifest.
- `signature.sig` - signature.

##### write json document

This job provides a `repo_map.json` file which contains comprehensive information about the container as well as the location of various files within our storage mechanism. This allows the Iron Bank website to retrieve the information for display on the Iron Bank website.

Job artifacts:
- `scan_metadata.json` - provides metadata from the scans.

#### publish

This stage will not run on feature branches.

The `publish` stage consists of multiple jobs:

- `harbor` - this stage will push built images to `registry1.dsop.io/ironbank` on master branch runs. This job does not run on development branches because the push to the Registry1 staging project occurs earlier in the pipeline.
- `upload to s3` - this stage will upload artifacts which are displayed/utilized by the Iron Bank website on master branch runs. The artifacts uploaded include scan reports, project README, project LICENSE, and others. This job will occur on development branch runs as well - it will push to a different S3 bucket than the master branch runsm 

#### vat

This stage will not run on project master or feature branches. 

The `vat` stage uses previous pipeline artifacts (notably, from the `scanning` stages) in order to populate the Vulnerability Assessment Tracker (VAT) at `vat.dsop.io`. VAT access is limited to container contributors, findings approvers, and container approvers. VAT contains the list of the findings associated with the built image in the pipeline, where those with access can justify findings and provide approvals. For those who are attempting to get their containers approved, they will need to provide their justifications for any scan results in the provided spreadsheets and work with a CHT member in order to submit justifications for review.
