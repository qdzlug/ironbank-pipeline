# ironbank-pipeline

## ironbank-pipeline directory structure

`/templates` contains the templates for the pipeline. This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the jobs required to run. This directory will also contain templates for special cases, such as distroless or scratch images. These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.

`/stages` contains the stages which are involved in pipeline execution. Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file. The `base.yaml` file dictates the actions and requirements needed for the stage to execute. Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Contributor project requirements for ironbank-pipeline use

- ### Adding a project pipeline in settings

The Iron Bank pipelines team will control the project configuration. As a result, projects _must not_ contain a `.gitlab-ci.yml` The Iron Bank Pipelines team has set up project templates which are used in the creation of the repo. The template provides a CI configuration path which enables the pipeline for the project.

The following steps outline how the custom CI configuration path is set:

`Settings` > `CI / CD` > `General pipelines` > `Custom CI configuration path`

The following is provided: `templates/default.yaml@ironbank-tools/ironbank-pipeline`

This will point the project towards the default pipeline in ironbank-pipeline.

The `default` template will allow images based on UBI to run through the required pipeline steps (whether the image directly uses an UBI base image for its base image, or by using an approved Iron Bank container with a base UBI image for its base image).

Please review templates/README.md for more information on which template your project needs.

## Pipeline artifacts

To access artifacts for each job, select the job in the UI on the `CI/CD -> Pipelines` page by clicking on the button for that job. In the top right hand corner of the screen, there is a box which says "Job artifacts" and contains buttons which say "Keep", "Download", and "Browse". Select the button which corresponds to the option you want.

Job artifacts are removed after one week in most cases. A new pipeline run will need to occur in order to produce job artifacts after this period of time.

## Pipeline stages

### preprocess

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

Job artifacts:

- pipeline templates/scripts/etc.

### preflight

The `preflight` stage performs multiple functions, which are described below:

- displaying the folder structure for the project which is running through the Container Hardening pipeline. The `folder structure` job will check for the existence of the following files and/or directories within the project which is being run through the pipeline:

  - README.md (required file)
  - Dockerfile (required file)
  - LICENSE (required file)
  - hardening_manifest.yaml (required, includes container metadata and allows external resources to be validated and used in the container build)
  - scripts (directory, not always required, which stores any script files needed in the container)
  - signatures (directory, not always required, which contains signatures needed for validation of any repository or external resource files)
  - config (directory, not always required, which stores any configuration files needed in the container)
  - accreditation (directory, not always required, which provides information about approved images)

- testing/checking the build variables exist using the `build variables` job.

- The `metadata.py` file processes the `hardening_manifest.yaml` file
  - The structure of the file is validated using the `hardening_manifest.schema.json` jsonschema.
  - The image name, version (first tag), tags, build args, and labels are extracted for use in later build steps

### lint

The `lint` stage contains multiple jobs and is used to ensure the formatting used in various project files is valid.

The `wl compare lint` job ensures that the pipeline run will fail on any branch if the repository structure is incorrect.

Job artifacts:

- project variables which are used in later pipeline stages.

TODO: A future version of the pipeline will also perform the following lints:

The `yaml lint` will lint the format yaml files for proper formatting in the project. `hardening_manifest.yaml` and any other yaml files will be linted.

`dockerfile lint` will run hadolint (or another linting tool) to lint the `Dockerfile`.

### import artifacts

The `import artifacts` stage will import any external resources (resources from the internet) provided in the `hardening_maifest.yaml` file for use during the container build. The `import artifacts` stage will download the external resources and validate that the checksums calculated upon download match the checksums provided in the `hardening_manifest.yaml` file.

Assuming this stage validates that the external resources are indeed the ones intended to be used within the container build, it passes along the external resources as artifacts in order to be used in the later `scan-artifacts` and `build` stages.

Job artifacts:

- (if provided) - external resources provided in `hardening_manifest.yaml` such as binaries, tarballs, RPMs, etc.
- (if provided) - images - a tar format of images pulled from public registries, as provided in `hardening_manifest.yaml`.

For more information on this stage, please refer to the `README.md` file [located here](https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/blob/master/stages/import-artifacts/README.md).

### scan artifacts

The `scan artifacts` stage performs an anti-virus/malware scan on the resources obtained in the `import artifacts` stage (if the `hardening_mainfest.yaml` file contains any `resources`). This will help guard against any malicious software/code being used in the container build. This stage utilizes ClamAV scans to perform the anti-virus/malware scanning. The scans database is updated each pipeline run, using the `freshclam` command, so that the list of vulnerabilities in the scanning database is always up to date.

The `scan artifacts` stage will automatically fail if there are infected files found in the resources downloaded in the `import artifacts stage`.

Job artifacts:

- (if external resources/images are used in the build process) `import-artifacts-clamav-report.txt` - contains the results of the ClamAV scan.

### build

The `build` stage builds the hardened container image. The build stage has access to any resources obtained in the `import artifacts` stage and access to the `Dockerfile` included in the container project repository. An egress policy has been set up to ensure that there are no external calls to the internet from this stage. The `build` stage utilizes the base image arguments provided in the project `Dockerfile` in order to build the project. It will pull approved versions of images from Harbor for use as the base image in the container build.

The `build` stage will push the built image to the Registry1 staging registry.

Job artifacts:

- image id as IMAGE_ID, image digest as IMAGE_PODMAN_SHA, staging image name (`<staging registry URL>/<image name>:<CI_PIPELINE_ID>`) as IMAGE_FULLTAG, image name as IMAGE_NAME

For more information on this stage, please refer to the `README.md` file [located here](https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/blob/master/stages/build/README.md).

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

### csv-output

The `csv-output` stage will generate CSV files for the various scans and the `<image-and-pipeline-id>-justifications.xlsx` file. These documents can be found in the artifacts for this stage.

The generated documents serve two purposes at the moment:

- the creation of `<image-and-pipeline-id>-justifications.xlsx` so that Container Hardening team members and vendors/contributors can access the list of findings for the container they are working on. The `<image-and-pipeline-id>-justifications.xlsx` file is a compilation of the findings generated from the Twistlock, Anchore, and OpenSCAP scans in the `scanning` stage and is used as the location for submitting justifications. This file is a result of running the `justifier.py` script against the `all-scans.xlsx` file in order to produce justifications for findings which have already been approved in parent images or other Iron Bank approved images.
- the CSV files from each of the scans are used by the VAT.

Job artifacts:

- `all_scans.xlsx` - compilation of all scan results in Microsoft Excel format.
- `anchore_gates.csv` - Anchore gates in CSV results.
- `anchore_security.csv` - Anchore security results in CSV format.
- `oscap.csv` - OpenSCAP results in CSV format.
- `<image-and-pipeline-id>-justifications.xlsx` - see description in previous paragraph.
- `summary.csv` - compilation of all scan results in CSV format.
- `tl.csv` - Twistlock results in CSV format.

### check cves

The `check cves` stage is configured to prevent the publishing of images which do not have whitelisted vulnerabilities. This stage checks the `dccscr-whitelists` repository to retrieve the whitelist for the image and will verify that the scan results generated from the `csv-output` stage do not contain any findings which have not been justified/whitelisted. This prevents the image from being published to the Iron Bank website or the Harbor registry with security vulnerabilities we are not aware of or have been justified and approved.

In time, this stage will utilize the VAT tool to compare the whitelisted vulnerabilities instead of the whitelists.

### Generate Allow Lists

#### Description

This stage only runs on master branch pipeline runs. Loads the anchore scan results and processes them in order to generate a whitelist of approved findings to be compared to the latest findings in a later stage.

#### Stage Dependencies

- load-scripts
- anchore-scan
- anchore-scan
- hardening-manifest
- build

#### Required Artiacts

#### Generated Artifacts

Artifacts are placed in the directory: ${ARTIFACT_STORAGE}/allowlists. The `ARTIFACT_STORAGE` variable is a variable in the pipeline. The value will not be documented as variables by their nature may change.

#### Required Python Libraries

- json
- logging
- os
- pathlib
- uuid

#### Code Overview

#### Main

```
def main() -> None:
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    logging.info("Generating whitelist for Anchore")
    vat_findings = json.loads(
        pathlib.Path(
            os.environ["ARTIFACT_STORAGE"], "lint", "vat_api_findings.json"
        ).read_text()
    )

    logging.debug(vat_findings)

    anchore = AnchoreAllowlister()
    anchore.policy(vat_findings=vat_findings)


if __name__ == "__main__":
    main()
```

- Set logging level and add some information based on whether it is `DEBUG` or `INFO`
- Set variable `vat_findings` to JSON object filled with data in `vat_api_findings.json`
- call class `AnchoreAllowLister` and set the returned data in variable `anchore`
- Call the `policy` method in class `anchore` and set the expected input `vat_findings` to the results of the previously filled variable vat_findings). (maybe this could be replaced by just doing `anchore.policy(vat_findings)`?)

##### AnchoreAllowLister Class

```
class AnchoreAllowlister:
    """
    Anchore Allowlist and Policy generator

    Contains the methods to generate an anchore allowist and mapping for an
    image in the IronBank Pipeline. The allowlist and mapping can both be
    returned in a typical Anchore Policy json.

    """

    def __init__(self):
        self.name = os.environ["IMAGE_NAME"].split("/")[-1]
        self.fullname = os.environ["IMAGE_NAME"].replace("/", "_")
        self.allowlist_id = f"{self.fullname}Allowlist"

    def mapping(self) -> dict:
        return {
            "comment": f"Anchore mapping for the {self.name} image",
            "id": f"{self.fullname}_mapping",
            "image": {"type": "tag", "value": "*"},
            "name": self.name,
            "policy_ids": [
                "default_policy_placeholder",
            ],
            "registry": None,
            "repository": None,
            "whitelist_ids": [self.allowlist_id],
        }
```

- initialize self
- Function to map the returned json object with the defined fields.

```
    def allowlist(self, vat_findings) -> dict:
        allowlist = {
            "comment": f"allowlist for {self.name}",
            "id": self.allowlist_id,
            "name": f"allowlist for {self.name}",
            "version": "1_0",
            "items": [],
        }

        allow = set()

        for finding in self.__filter_vat_for_anchore(vat_findings):
            for ac in self.__anchore_scan_findings():
                if (
                    ac["Trigger_Id"]
                    in f"{finding['identifier']}+{finding.get('package')}"
                ):
                    allow.add(
                        (
                            finding["contributor"]["justification"],  # comment
                            ac["Gate"],  # gate
                            str(uuid.uuid4()),  # id
                            ac["Trigger_Id"],  # trigger_id
                        )
                    )

        allowlist["items"] = [
            {
                "comment": a[0],
                "gate": a[1],
                "id": a[2],
                "trigger_id": a[3],
            }
            for a in allow
        ]

        return allowlist
```

- build allowset json object with defined fields
- Add a finding from VAT to list `allow`
- create dict of each item in list `allow` in allowlist json object

```
    def policy(self, vat_findings, filename="anchore_allowlist.json") -> dict:
        policy = {
            "blacklisted_images": [],
            "description": f"IronBank Anchore allowlist for the {os.environ['IMAGE_NAME']} image.",
            "id": str(uuid.uuid4()),
            "mappings": [self.mapping()],
            "name": f"{self.name}_ironbank_allowlist",
            "policies": [
                {
                    "comment": "Default Policy Placeholder",
                    "id": "default_policy_placeholder",
                    "name": "DefaultPolicy",
                    "rules": [],
                    "version": "1_0",
                }
            ],
            "version": "1_0",
            "whitelisted_images": [],
            "whitelists": [self.allowlist(vat_findings=vat_findings)],
        }

        logging.debug(json.dumps(policy))
        pathlib.Path(os.environ["ALLOWLISTS"]).mkdir(parents=True, exist_ok=True)
        pathlib.Path(os.environ["ALLOWLISTS"], filename).write_text(json.dumps(policy))

        return policy
```

- Create policy json object with defined fields
- Write the json object to a file

```
    def __filter_vat_for_anchore(self, vat_findings) -> list:
        return [
            finding
            for finding in vat_findings["findings"]
            if finding["findingsState"].lower() in ["approved", "conditional"]
            and finding["source"].lower() in ["anchore_comp", "anchore_cve"]
        ]
```

- return findings that are approved or conditionally approved and if it is an anchore compliance or cve finding

```
    def __anchore_scan_findings(self) -> list:
        """
        Grab the raw anchore compliance json and extract the compliance findings.

        """
        imageid = os.environ["IMAGE_ID"].split(":")[-1]

        anchore_compliance = json.loads(
            pathlib.Path(
                os.environ["ARTIFACT_STORAGE"],
                "scan-results",
                "anchore",
                "anchore_gates.json",
            ).read_text()
        )
        logging.debug(anchore_compliance)

        header = anchore_compliance[imageid]["result"]["header"]
        rows = anchore_compliance[imageid]["result"]["rows"]
        return [dict(zip(header, row)) for row in rows]
```

- Grab the raw anchore compliance json and extract the compliance findings.
- Load the JSON into variable `anchore_compliance`
- set header and rows values and then return the combine d values as a dict to be written as a csv

### documentation

This stage will not run on feature branches.

The `documentation` stage consists of three scripts called in the job's base yaml file.

- #### sign-image-run.sh

This job will do a GPG signing of the image with the Iron Bank public key so that end users can validate that the image is from the Iron Bank and the one they intend to download.

Job artifacts:

- `<image-version.sig>` - signature of the image.
- `<image-version.tar>`- tar file of the signed image.
- variable IMAGE_TAR_SHA which is the sha256sum of the image tarball created by the `skopeo copy`

#### sign-manifest-run.sh

This job utilizes the Iron Bank public GPG key in order to sign the container manifest.

Job artifacts:

- `manifest.json` - signed manifest.
- `signature.sig` - signature.

#### write-json-docs.json

This job provides a `repo_map.json` file which contains comprehensive information about the container as well as the location of various files within our storage mechanism. This allows the Iron Bank website to retrieve the information for display on the Iron Bank website.

Job artifacts:

- `scan_metadata.json` - provides metadata from the scans.

### publish

This stage will not run on feature branches.

The `publish` stage consists of multiple jobs:

- `harbor` - this stage will push built images to `registry1.dsop.io/ironbank` on master branch runs. This job does not run on development branches because the push to the Registry1 staging project occurs earlier in the pipeline.
- `upload to s3` - this stage will upload artifacts which are displayed/utilized by the Iron Bank website on master branch runs. The artifacts uploaded include scan reports, project README, project LICENSE, and others. This job will occur on development branch runs as well - it will push to a different S3 bucket than the master branch runsm

### vat

This stage will not run on project master or feature branches.

The `vat` stage uses previous pipeline artifacts (notably, from the `scanning` stages) in order to populate the Vulnerability Assessment Tracker (VAT) at `vat.dsop.io`. VAT access is limited to container contributors, findings approvers, and container approvers. VAT contains the list of the findings associated with the built image in the pipeline, where those with access can justify findings and provide approvals. For those who are attempting to get their containers approved, they will need to provide their justifications for any scan results in the provided spreadsheets and work with a CHT member in order to submit justifications for review.
