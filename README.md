# ironbank-pipeline

## Contributor project requirements for ironbank-pipeline use:
- `.gitlab-ci.yml` file with an $IMG_VERSION variable set

## ironbank-pipeline directory structure:

`/templates` contains the templates for the pipeline. This includes the `globals.yaml` file, which contains variable references needed for each CI/CD job to run and outlines the jobs required to run. This directory will also contain templates for special cases, such as distroless or scratch images. These special cases will have their own `.yaml` files which override aspects of the `globals.yaml` configuration as needed.


`/stages` contains the stages which are involved in pipeline execution. Each stage of the pipeline has its own folder within this directory containing a `base.yaml` file. The `base.yaml` file dictates the actions and requirements needed for the stage to execute. Additional `.yaml` files can be present within the stage directories in order to separate the jobs which occur within that particular stage.

## Pipeline stages

#### preflight

The `preflight` stage performs two functions:
    - displaying the folder structure for the project which is running through the Container Hardening pipeline.
    - testing/checking the build variables exist.

The preflight stage is currently set to allow failures.

#### lint

The `lint` stage contains multiple jobs and is used to ensure the formatting used in various project files is valid.

The `yaml lint` and `dockerfile lint` jobs are used to ensure the proper formatting of the following files in each project: `.gitlab-ci.yml`, `download.yaml`/`download.json` file, and `Dockerfile`. 

The `wl compare lint` job ensures that the pipeline run will fail on any branch if the repository structure is incorrect, or if the greylist files can't be retrieved or have a mismatched image name/tag.
