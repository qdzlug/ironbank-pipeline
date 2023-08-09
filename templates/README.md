# templates

_This page is for informational purposes only to provide visibility into the Iron Bank pipeline. Contributors should work with the Iron Bank pipelines team in order to have the appropriate template selected for their project if it is different from the default pipeline configuration._

This directory contains yaml files which dictate which pipeline steps should be run for particular projects. It is necessary to use pipeline templates due to the difference in hardened base images which are used to produce different containers. For example, the `distroless` base image is not compatible with OpenSCAP scanning features, so the `distroless` template omits those scanning jobs.

There is a `globals.yaml` file which defines all of the possible stages which can be utilized in a pipeline. It also includes variables which are inherited by the pipelines. It is in the `globals.yaml` file where the default image is specified for use in each job. There are certain jobs which specify another image, which overrides the default image. Each of the pipeline templates specify the base file for each of the stages defined in the `globals.yaml` file.

The list of templates is as follows:

- `ubi.yaml` - this is the default template used with projects which have UBI base images. This is the template which the majority of images use. All of the pipeline steps are present.
- `distroless.yaml` - this is the template for container builds which utilize the base distroless image, [which can be found here](https://repo1.dsop.io/dsop/google/distroless/base). The distroless template does not contain OpenSCAP scanning due to a lack of compatibility with the tool.
- `development.yaml` - this template is for testing the `development` branch of the Iron Bank pipeline and should not be included in any project repos.
- `ubuntu.yaml` - this template is used with projects which have Ubuntu base images. The Ubuntu template uses a custom ubuntu image for openscap scanning. Openscap requires that the image used for scanning has the same base image as the image being scanned.
