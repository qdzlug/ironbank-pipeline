# preflight

The `preflight` stage is used to check for a handful of files in project repositories. The checks are made to enforce Container Hardening repository requirements.This stage will also check for required build variables in order to prevent failures later in the pipeline if they are missing.

The following files are checked in the `preflight` stage, and the stage will fail if these files are not included in the project repository:

- `README.md` - this file is required in order to have a hardened container approved.
- `Dockerfile` - the build stage will fail if a `Dockerfile` is not found in the project repository. It is checked for here in the `preflight` stage in order to reduce resources for a project which would not have a passing pipeline. Please refer to the Container Hardening Contributor Onboarding guide for guidance on the content to include in the `README.md` file.
- `LICENSE` files - acceptable extensions include `.md`, `.txt`, and `.adoc`. 

The `preflight` stage will also check for the presence of the `IMG_VERSION` variable in the project repository. This variable must be set in order to properly tag the built container in Registry1 and on the Iron Bank website.