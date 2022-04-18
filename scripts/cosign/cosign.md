# Cosign Signatures

The Iron Bank pipeline is now performing cosign signatures on all images pushed to the `ironbank` project within Registry1.

Please see the adjacent pem file, `cosign-certificate.pem` for the public cert used to verify these signatures.

The CA bundle cert can be used to validate the `cosign-certificate.pem` file's authenticity.

## Verifying a Signature

To verify a signature, make sure you have [`cosign` installed](https://github.com/sigstore/cosign#installation).

```log
cosign validate --cert <path-to-cosign-certificate.pem> registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.5
```

or

```log
openssl x509 -in <path-to-cosign-certificate.pem> -noout -pubkey >cosign.pem
cosign verify --key cosign.pem registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.5
```

A successful verify command will display the following

```log
Verification for registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.5 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

## Pulling Additional Artifacts

If using `cosign download [command]`, the output will be sent to stdout.
It is recommended to use either `--output-file` or pipe this output to another command.

## Signature

There are a few ways a signature can be pulled from the registry.
The easiest way to access a signature is to use `cosign download signature`

## Attestation

Attestation artifacts have tags ending in `.att`.
These can be pulled by using `cosign download` or `skopeo copy`

### cosign

To access the predicate file uploaded as a cosign attestation, look at the `.payload` and base64 decode this value.
The predicate file contents can then be found at `.predicate`.
The following script will pipe stdout to jq to access the `.predicate`, and save this to a file.

```bash
cosign download attestation registry1.dso.mil/ironbank/docker/scratch:ironbank | jq '.payload | @base64d | fromjson | .predicate' >vat_response.json
```

### skopeo

skopeo can be installed by following [these instructions](https://github.com/containers/skopeo/blob/main/install.md).

To `skopeo copy` an artifact, you will need to know the image digest the artifact relates to.
The directory created by the copy will include a manifest file and the layer containing the predicate file.
To find the digest of the predicate file, look at the digest at `.layers[].digest` in the manifest file.

```sh
skopeo copy docker://registry1.dso.mil/ironbank/docker/scratch:sha256-<digest>.att dir:output-dir
jq '.payload | @base64d | fromjson | .predicate' output-dir/<attestation-digest> >vat_response.json
```

## SBOM

The simplest way to get the sbom artifacts is to use cosign and oras.
This command will produce one file per layer of the SBOM artifact.

Oras can be installed by following [these instructions](https://oras.land/cli/).

```bash
artifact=$(cosign triangulate --type sbom registry1.dso.mil/ironbank/docker/scratch:ironbank)
cosign verify --key cosign.pem "${artifact}"
oras pull --allow-all "${artifact}"
```
