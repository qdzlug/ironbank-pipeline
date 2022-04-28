# Cosign Signatures

The Iron Bank pipeline is now performing cosign signatures on all images pushed to the `ironbank` project within Registry1.

Please see the adjacent pem file, `cosign-certificate.pem` for the public cert used to verify these signatures.

The CA bundle cert can be used to validate the `cosign-certificate.pem` file's authenticity.

## Verifying a Signature

To verify a signature, make sure you have [`cosign` installed](https://github.com/sigstore/cosign#installation).
The path to the certificate file can be a URL or a file path.

```bash
cosign verify --cert <path-to-cosign-certificate.pem> registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.5
```

```bash
cosign verify --cert https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/raw/master/scripts/cosign/cosign-certificate.pem registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.5
```

A successful verify command will display the following

```log
Verification for registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.5 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

## Pulling Cosign Artifacts

Beyond creating image signatures, Cosign can be used to generate additional artifacts in support of software supply chain security, such as image SBOMs and Attestations.

These artifacts, as well as their own signature artifacts, can be downloaded and verified using tools such as `cosign` and `oras`, as described in the following sections.

If using `cosign download [command]`, the output will be sent to stdout.
It is recommended to use either `--output-file` or pipe this output to another command.

## Signature

The easiest way to access a signature is to use `cosign download signature`

```bash
cosign download signature <image uri>
```

## Attestation

Attestation artifacts have tags ending in `.att`.

To access the predicate file uploaded as a cosign attestation, look at the `.payload` and base64 decode this value.
The predicate file contents can then be found at `.predicate`.
The following script will pipe stdout to jq to access the `.predicate`, and save this to a file.

```bash
cosign verify-attestation --cert https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/raw/master/scripts/cosign/cosign-certificate.pem registry1.dso.mil/ironbank/docker/scratch:ironbank | jq '.payload | @base64d | fromjson | .predicate'
```

## SBOM

The simplest way to get the sbom artifacts is to use cosign and oras.
This command will produce one file per layer of the SBOM artifact.

Oras can be installed by following [these instructions](https://oras.land/cli/).

```bash
artifact=$(cosign triangulate --type sbom registry1.dso.mil/ironbank/docker/scratch:ironbank)
cosign verify --cert https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/raw/master/scripts/cosign/cosign-certificate.pem "${artifact}"
oras pull --allow-all "${artifact}"
```
