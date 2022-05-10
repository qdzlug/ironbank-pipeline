# preflight

The `preflight` stage is used to check for a handful of files in project repositories. The checks are made to enforce Container Hardening repository requirements. This stage will also check for required build variables in order to prevent failures later in the pipeline if they are missing.

## folder structure

The following files are checked in the `folder structure` job of the `preflight` stage, and the stage will fail if these files are not included in the project repository:

- `README.md` - this file is required in order to have a hardened container approved.
- `Dockerfile` - the build stage will fail if a `Dockerfile` is not found in the project repository. It is checked for here in the `preflight` stage in order to reduce resources for a project which would not have a passing pipeline. Please refer to the Container Hardening Contributor Onboarding guide for guidance on the content to include in the `README.md` file.
- `LICENSE` files - acceptable extensions include `.md`, `.txt`, and `.adoc`.
- `clamav-whitelist` file and `CLAMAV_WHITELIST` CI variable existence. If either exists without the other, we fail the job.
- `trufflehog-config.yaml` file and `TRUFFLEHOG_CONFIG` CI variable existence. Again, if either exists without the other, we fail the job.

## hardening_manifest

The `hardening_manifest` job will run the `metadata.py` script which validates the project's `hardening_manifest.json` file using `jsonschema` and the `hardening_manifest_schema.json` file in the pipeline's `schema` directory.

## trufflehog

The [`trufflehog`](https://github.com/feeltheajf/trufflehog3) job runs the `trufflehog.py` script which uses `subprocess` to run `trufflehog3` against a project's code to search for secrets that may have been committed.

The job can accept a config file as long as it is named `trufflehog-config.yaml` and it is in the root of a project and a project or group level CI variable named `TRUFFLEHOG_CONFIG` exists. The value of the variable can be anything, as long as it is not blank/empty in the UI.

An example config file looks like the following

```yaml
exclude:
  - message: Ignore secretstorage
    # These are the false positives we want to ignore
    # will only be skipped in corresponding files
    pattern: secretstorage
    paths:
      - config/linux-64/repodata.json
```
