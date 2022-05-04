# Star Gate

## Job Purpose

The Star Gate (SG) job will publish images to a provided S3 bucket, which SG will process in order to promote Iron Bank (IB) images to higher impact levels (IL)s

## Dependencies

- build
- S3

## Workflow

1. Create a temp directory for storing these artifacts
   - Import artifacts from the S3 stage. We will want to use the `reports/` directory from these artifacts for our body of evidence (BOE)
   - Remove xlsx files from `reports/` directory
   - Create an OCI directory using `skopeo`. e.g. `skopeo copy docker://registry1.dso.mil/ironbank-staging/redhat/ubi/ubi8@sha256:<shasum> oci:ubi8:<IMAGE_VERSION>`
   - Generate a metadata file as defined in [this ticket](https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/issues/364#note_368866). Also output this metadata one directory above this temp dir
1. Create a tar.gz archive of the files and directories in the temp directory
1. GPG sign archive
1. Upload archive, signatures, and metadata file to provided S3 bucket using Boto3
