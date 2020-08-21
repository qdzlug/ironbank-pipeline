# ironbank-pipeline


## Dependencies

Install Python dependencies with the following command:
```
pip install -r requirements.txt
```

## Running Tests

The Python `nose` package is used for finding, running, and assessing the coverage of the unit tests.

Run the tests with the following command:
```
nosetests --with-cov
```
## Tranlational Information

There were a lot of "common" functions in Arguments.groovy and the corresponding functionality in `common.py` has been documented in that file.




## Contributor project requirements for ironbank-pipeline use:
- `.gitlab-ci.yml` file with an $IMG_VERSION variable set

## ironbank-pipeline directory structure:

`/templates` contains the templates for the pipeline. This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the jobs required to run. This directory will also contain templates for special cases, such as distroless or scratch images. These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.


`/stages` contains the stages which are involved in pipeline execution. Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file. The `base.yaml` file dictates the actions and requirements needed for the stage to execute. Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Pipeline stages

#### preprocess

This stage is used to clone the `ironbank-pipeline` repository from GitLab so that the templates/stages contained within the project can be utilized in later pipeline stages.

#### preflight

The `preflight` stage performs two functions:
    - displaying the folder structure for the project which is running through the Container Hardening pipeline. The `folder structure` job will check for the existence of the following files and/or directories within the project which is being run through the pipeline:
        - README (required file)
        - Dockerfile (required file)
        - LICENSE (required file)
        - download.yaml (file, not always required)
        - scripts (directory, not always required)
        - signatures (directory, not always required)
        - config (directory, not always required)
        - accreditation (directory, not always required)
    - testing/checking the build variables exist using the `build variables` job.

The preflight stage is currently set to allow failures because the `folder structure` job is listing some optional files/directories

#### lint

The `lint` stage contains multiple jobs and is used to ensure the formatting used in various project files is valid.

The `yaml lint` and `dockerfile lint` jobs are used to ensure the proper formatting of the following files in each project: `.gitlab-ci.yml`, `download.yaml`/`download.json` file, and `Dockerfile`. 

The `wl compare lint` job ensures that the pipeline run will fail on any branch if the repository structure is incorrect, or if the greylist files can't be retrieved or have a mismatched image name/tag.